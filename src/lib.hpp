#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>

#include <map>
#include <string>
#include <vector>

#include "cgroups.hpp"
#include "config.hpp"
#include "json/json"
#include "rules.hpp"
#include "runstats_json_impl.hpp"

#include "cpp-base/logger.hpp"
#include "cpp-base/os.hpp"
#include "cpp-base/string_utils.hpp"
#include "cpp-base/time.hpp"

using std::string;
using std::vector;
using std::pair;

using Base::Msg;
using Base::Die;

CGroups cg;

class ProcessKeeper {
  public:
    ProcessKeeper(ProcessConfig config, int pid, int errorPipes[2]);

    ProcessConfig config;  /// time limits and such
    int processPid;        /// pid of the isolate process (initially cloned, than execved)
    int errorPipes[2];     /// write erros to errorPipes[0]

    PreciseTimer wallClock;  /// mesures the wall time from the start of the sandbox process

    RunStats processStats;  /// keeps process data in case it was killed by TLE

    /// signal handlers
  public:
    static void alarmSignalHandler(int signum);

    static void dummySignalHandler(int signum);

    /// signal related functions
  protected:
    void mockSignals() {
        struct sigaction sa;
        bzero(&sa, sizeof(sa));
        sa.sa_handler = ProcessKeeper::dummySignalHandler;
        sigaction(SIGHUP, &sa, NULL);
        sigaction(SIGINT, &sa, NULL);
        sigaction(SIGQUIT, &sa, NULL);
        sigaction(SIGILL, &sa, NULL);
        sigaction(SIGABRT, &sa, NULL);
        sigaction(SIGFPE, &sa, NULL);
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGPIPE, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGUSR1, &sa, NULL);
        sigaction(SIGUSR2, &sa, NULL);

        /// mock alert sig as well since it can be overwriteSize
        sigaction(SIGALRM, &sa, NULL);
    }

    void clearTimer() {
        startStatusCheck(0);
    }

    void startStatusCheck(unsigned long long checkIntervalMs) {
        /// setup callback for SIGALRM signal
        struct sigaction sa;
        bzero(&sa, sizeof(sa));
        sa.sa_handler = ProcessKeeper::alarmSignalHandler;
        sigaction(SIGALRM, &sa, NULL);

        /// setup initial time and interval time for signal triggering
        itimerval timer;

        timer.it_interval.tv_sec = checkIntervalMs / 1000;
        timer.it_interval.tv_usec = (checkIntervalMs % 1000) * 1000;
        timer.it_value = timer.it_interval;

        if (setitimer(ITIMER_REAL, &timer, NULL) != 0) {
            Die("ERROR: setitimer failed");
            exit(-1);
        }
    }

    /// get stats about process
  protected:
    unsigned long long getProcTimeMs() { return cg.cpuTimeMs(); }

    unsigned long long getWallTimeMs() { return wallClock.msElapsed(); }

    int getMemoryKB() { return cg.memoryKB(); }

    void updateStats() {
        processStats.update(cg.getFullTime());
        processStats.timeStat.wallTimeMs = getWallTimeMs();
        processStats.memoryKB = getMemoryKB();
    }

    /// called from signal handlers in case something went of grid.
  public:
    void killProcess(RunStats::ResultCode killReason, string internalMessage = "") {
        clearTimer();

        kill(-processPid, SIGKILL);
        kill(processPid, SIGKILL);

        struct rusage rus;
        int p, stat;

        do {
            p = wait4(processPid, &stat, 0, &rus);
        } while (p < 0 && errno == EINTR);

        processStats.processWasKilled = true;
        processStats.update(killReason);
        processStats.update(rus);
        processStats.exitCode = 0;
        processStats.internalMessage = internalMessage;

        updateStats();
    }

    RunStats::ResultCode checkLimits() {
        if (config.cpuTimeLimitMs && getProcTimeMs() >= config.cpuTimeLimitMs + config.extraTimeMs) {
            return RunStats::TIME_LIMIT_EXCEEDED;
        }

        if (config.wallTimeLimitMs && getWallTimeMs() >= config.wallTimeLimitMs + config.extraTimeMs) {
            return RunStats::WALL_TIME_LIMIT_EXCEEDED;
        }

        if (config.memoryLimitKB && getMemoryKB() >= config.memoryLimitKB) {
            return RunStats::MEMORY_LIMIT_EXCEEDED;
        }

        return RunStats::OK;
    }

  public:
    RunStats startKeeper() {
        /// start clock even thou it is already started by the constructor
        wallClock.start();

        /// switch error pipes fd to read errors from the child process in which the
        /// process runs
        close(errorPipes[1]);

        mockSignals();

        /// if checkIntervalMs is not null, status check is on
        if (config.checkIntervalMs) {
            startStatusCheck(config.checkIntervalMs);
        }

        while (1) {
            struct rusage processUsage;
            int processStatus;

            pid_t p;
            p = wait4(processPid, &processStatus, 0, &processUsage);

            /// check if the process was killed by the signal
            if (processStats.processWasKilled) {
                return processStats;
            }

            /// check if wait4 is working properly
            if (p < 0) {
                if (errno == EINTR) {
                    continue;
                }
                Die("wait4: %m");
            }

            /// sanity check
            if (p != processPid) {
                Die("wait4: unknown pid %d exited!", p);
            }

            clearTimer();

            /// Check error pipe if there is an internal error passed from inside the box
            char interr[Base::kDieBufferSize];
            int n = read(errorPipes[0], interr, sizeof(interr) - 1);
            if (n > 0) {
                interr[n] = 0;
                Die("childErrors", interr, true);
            }

            updateStats();
            processStats.update(processUsage);
            Msg("ProcessStatus:%d\n", processStatus);

            if (WIFEXITED(processStatus)) {
                /// the process exited normaly.
                if (WEXITSTATUS(processStatus)) {
                    processStats.resultCode = RunStats::NON_ZERO_EXIT_STATUS;
                    processStats.exitCode = WEXITSTATUS(processStatus);
                } else {
                    processStats.resultCode = RunStats::OK;
                    processStats.exitCode = 0;
                }
            } else if (WIFSIGNALED(processStatus)) {
                processStats.resultCode = RunStats::RUNTIME_ERROR;
                processStats.terminalSignal = WTERMSIG(processStatus);
            } else if (WIFSTOPPED(processStatus)) {
                processStats.resultCode = RunStats::ABNORMAL_TERMINATION;
                Die("Process has stopped. Won't try to start it again.");
            } else {
                processStats.resultCode = RunStats::INTERNAL_ERROR;
                Die("wait4: unknown status %x, giving up!", processStatus);
            }

            if (checkLimits() != RunStats::OK) {
                processStats.resultCode = checkLimits();
            }

            return processStats;
        }
    }
} * processKeeper;  /// required for signal handler. need to redirect the
                    /// handling process to the processKeeper object

ProcessKeeper::ProcessKeeper(ProcessConfig config, int processPid, int errorPipes[2]) : processStats() {
    this->config = config;
    this->processPid = processPid;
    this->errorPipes[0] = errorPipes[0];
    this->errorPipes[1] = errorPipes[1];
    processKeeper = this;
}

void ProcessKeeper::alarmSignalHandler(int UNUSED signum) {
    /// signal callback must be static method / function
    /// it calls the processKeeper pointer which is set up in
    /// initProcessKeeper function
    RunStats::ResultCode status = processKeeper->checkLimits();
    if (status != RunStats::OK) {
        processKeeper->killProcess(status);
    }
};

/// capture misc signals so it doesn't just crash
void ProcessKeeper::dummySignalHandler(int signum) {
    processKeeper->killProcess(RunStats::INTERNAL_ERROR,
                               Base::StrCat("Keeper got an unexpected signal:", signum));
};

class ProcessInitialiser {
  public:
    static int ASyncStart(void*);

  public:
    ProcessInitialiser(ProcessConfig config, int uid, int gid, int errorPipes[2]) {
        this->config = config;
        this->uid = uid;
        this->gid = gid;
        this->errorPipes[0] = errorPipes[0];
        this->errorPipes[1] = errorPipes[1];
    }

    ProcessConfig config;
    int uid;
    int gid;
    int errorPipes[2];

    /// sets up everything so that the process will be run in a controlled
    /// sandbox as specified by the config given
    void setupSystem() {
        Base::die_fd = errorPipes[1];
        close(errorPipes[0]);

        cg.enter();
        setupRoot();
        setupPipes();
        setupFilePermissions();
        setupRlimits();
        setupCredentials();

        /// changes dir before executin to dir provided from flag / set dir
        if (config.execDirectory.size() && chdir(config.execDirectory.c_str())) {
            Die("chdir: %m");
        }
    }

  protected:
    /// creates a root/ folder in the sandbox dir
    /// mounts the root/ folder as ramdisk
    /// mounts bin, dev, lib, lib64, proc, usr into root/
    /// mounts the box folder from which the out/err/meta are collected after the run
    /// changes the root of the process to root/
    /// changes the dir to box/ (root/box)
    void setupRoot() {
        Base::MakeDir("root", 0750);

        /*
         * Ensure all mounts are private, not shared. We don't want our mounts
         * appearing outside of our namespace.
         * (systemd since version 188 mounts filesystems shared by default).
         */
        if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) Die("Cannot privatize mounts: %m");

        /// mount root folder as ramdisk so all writes/reads from files will be fast a.f.
        /// mounts nothing("none") as a folder root which will be seen
        if (mount("none", "root", "tmpfs", 0, "mode=755") < 0) Die("Cannot mount root ramdisk: %m");

        Rules::DirRules dirRules(config.dirRules);
        dirRules.applyRules();

        if (chroot("root") < 0) Die("Chroot failed: %m");

        if (chdir("root/box") < 0) Die("Cannot change current directory: %m");

        /// TODO(@velea) why doesn't Makedir apply permissions mod?
        Base::MakeDir("/tmp", 0777);
        Base::RChmod(" 777 /tmp ");
    }

    /// apply permissions for the process uid
    /// std{in,out,err} permissions and auto binary exec permission and custom permissions
    /// uses setfacl(/usr/bin/setfacl)[apt install -acl]
    void setupFilePermissions() {
        Rules::FilePermissions filePermissions(config.filePermissions);
        filePermissions.applyRules(uid);
    }

    void setupCredentials() {
        if (setresgid(gid, gid, gid) < 0) {
            Die("setresgid: %m");
        }

        if (setgroups(0, NULL) < 0) {
            Die("setgroups: %m");
        }

        if (setresuid(uid, uid, uid) < 0) {
            Die("setresuid: %m");
        }

        setpgrp();
    }

    /// redirect std{in,out,err}
    void setupPipes() {
        if (config.swapPipeOpenOrder == false) {
            if (config.redirectStdin.size()) {
                close(0);
                if (open(config.redirectStdin.c_str(), O_RDONLY) != 0) {
                    Die("open(\"%s\"): %m", config.redirectStdin.c_str());
                }
            }

            if (config.redirectStdout.size()) {
                close(1);
                if (open(config.redirectStdout.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666) != 1) {
                    Die("open(\"%s\"): %m", config.redirectStdout.c_str());
                }
            }
        } else {
            if (config.redirectStdout.size()) {
                close(1);
                if (open(config.redirectStdout.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666) != 1) {
                    Die("open(\"%s\"): %m", config.redirectStdout.c_str());
                }
            }

            if (config.redirectStdin.size()) {
                close(0);
                if (open(config.redirectStdin.c_str(), O_RDONLY) != 0) {
                    Die("open(\"%s\"): %m", config.redirectStdin.c_str());
                }
            }
        }

        if (config.redirectStderr.size()) {
            close(2);
            if (open(config.redirectStderr.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666) != 2) {
                Die("open(\"%s\"): %m", config.redirectStderr.c_str());
            }
        } else {
            dup2(1, 2);
        }
    }

    string getRlimitName(int resource) {
        static std::map<int, string> resource_name = {
            {RLIMIT_AS, "RMLIMIT_AS"},        {RLIMIT_FSIZE, "RMLIMIT_FSIZE"},     {RLIMIT_STACK, "RMLIMIT_STACK"},
            {RLIMIT_NOFILE, "RLIMIT_NOFILE"}, {RLIMIT_MEMLOCK, "RMLIMIT_MEMLOCK"}, {RLIMIT_NPROC, "RMLIMIT_NPROC"},
        };

        return resource_name[resource];
    }

    void setRlimit(int resource, rlim_t limit) {
        struct rlimit rl;
        bzero(&rl, sizeof(rl));
        rl.rlim_cur = limit;
        rl.rlim_max = limit;

        if (setrlimit(resource, &rl) < 0) {
            Die("setrlimit(%s, %jd)", getRlimitName(resource).c_str(), (intmax_t)limit);
        }
    }

    /// set limits on process
    void setupRlimits() {
        /// max file limit
        if (config.fileSizeLimitKB) {
            setRlimit(RLIMIT_FSIZE, (rlim_t)config.fileSizeLimitKB * 1024);
        }

        /// stack limit
        if (config.stackLimitKB) {
            setRlimit(RLIMIT_STACK, (rlim_t)config.stackLimitKB * 1024);
        } else {
            setRlimit(RLIMIT_STACK, RLIM_INFINITY);
        }

        /// max opened files at once
        setRlimit(RLIMIT_NOFILE, (rlim_t)64);

        /// prevents the process from locking memory into RAM - preventing
        /// the os to move the memory to swap space
        setRlimit(RLIMIT_MEMLOCK, (rlim_t)0);

        /// max num of processes/threads that can be created
        if (config.maxProcesses) {
            setRlimit(RLIMIT_NPROC, (rlim_t)config.maxProcesses);
        }
    }
};

int ProcessInitialiser::ASyncStart(void* args) {
    ProcessInitialiser* initialiser = (ProcessInitialiser*)args;
    initialiser->setupSystem();

    Msg("Provided run command:%s\n", initialiser->config.runCommand.c_str());

    char** processArgs = Base::StringToCharSS(Base::ParseCommandLine(initialiser->config.runCommand));
    auto environment = Rules::Environment(initialiser->config.environment);
    char** env = environment.getEnvironment();

    /// child process inherits everything from parent
    /// * opened std{in,out,err}
    /// * cpu, mem, disk, network limits
    /// * cgroup id (associated with limits)
    /// * pwd, relative root
    /// all these limitations can't be enlarged, only reduced/shrinked

    char** c = processArgs;
    while (*c != nullptr) {
        Msg("Run command:\t%s\n", *c);
        c++;
    }

    execvpe(processArgs[0], processArgs, env);
    Die("execvpe(%s): %m", processArgs[0]);

    return 0;
}

class Jailer {
  public:
    static int firstProcessUid;
    static int firstProcessGid;
    static int firstCgroupId;
    static int maxProcessesPerCG;
    static string baseBoxDir;

    ProcessConfig config;
    void* isolatedProcessStack;

    string boxDir;  /// box directory inside baseBoxDir
    int uid;
    int gid;
    int cgid;
    int meta_fd;

    Jailer(const ProcessConfig& config, void* isolatedProcessStack = nullptr)
          : config(config), isolatedProcessStack(isolatedProcessStack) {
        /// sanity check
        if (config.boxId == -1) {
            Die("Specify box-id.");
        }

        if (config.processId < 0 or config.processId >= maxProcessesPerCG) {
            Die("Process if out of range [0, %d). Id=%d", maxProcessesPerCG, config.processId);
        }

        uid = firstProcessUid + maxProcessesPerCG * config.boxId + config.processId;
        gid = firstProcessGid + maxProcessesPerCG * config.boxId + config.processId;
        cgid = firstCgroupId + maxProcessesPerCG * config.boxId + config.processId;

        boxDir = Base::StrCat(baseBoxDir, "/", config.boxId);
        this->meta_fd = -1;
    }

    ~Jailer() { close(meta_fd); }

    void PrintStats(const RunStats& stats) {
        if (meta_fd != -1) {
            string stats_str;
            if (config.legacyMetaJson) {
                stats_str = stats.toJson();
            } else {
                stats_str = Json(stats).Stringify(false);
            }

            Base::xwrite(meta_fd, stats_str.c_str(), stats_str.size());
        }
    }

    void BoxInit() {
        if (config.metaFile.size()) {
            meta_fd = open(config.metaFile.c_str(), O_WRONLY | O_TRUNC | O_CREAT, 0777);
        }

        umask(0027);  // new files will be created with 0750

        Base::MakeDir(boxDir.c_str());
        if (chdir(boxDir.c_str()) < 0) {
            Die("chdir(%s): %m", boxDir.c_str());
        }

        cg.init(cgid);
        cg.cgMemoryLimitKB = config.memoryLimitKB;
    }

    void Start() {
        Base::verbose_level = config.verboseLevel;

        BoxInit();
        typedef ProcessConfig::Modes Modes;
        switch (config.mode) {
            case Modes::kUnspecified:
                Die("Specify a mode for isolate");
                break;
            case Modes::kInit:
                Init();
                break;
            case Modes::kRun:
                Run();
                break;
            case Modes::kCleanup:
                Cleanup();
                break;
            default:
                Die("Unknown mode");
                break;
        }
    }

    void Init() {
        Msg("Preparing sandbox directory\n");
        Base::RMTree("box");
        Base::MakeDir("box", 0750);

        cg.prepare();

        Rules::DiskQuota diskQuota(config.diskQuota, uid);
        diskQuota.applyQuota();
    }

    void Cleanup() {
        if (!Base::DirExists("box")) {
            Msg("Box directory not found, there isn't anything to clean up");
        } else {
            Msg("Deleting sandbox directory\n");
            Base::RMTree(boxDir.c_str());
        }

        cg.cleanup();
    }

    void WriteErrorStats() {
        // Better safe than sorry
        // Print an error stat to HDD in case something goes really really bad
        RunStats errorStats;
        errorStats.internalMessage = "No results provided.";
        errorStats.resultCode = RunStats::INTERNAL_ERROR;
        PrintStats(errorStats);
    }

    void Run() {
        Msg("Start running\n");

        if (!Base::DirExists("box")) {
            Die("Box directory not found, did you run 'isolate --init'?");
        }

        cg.prepare();  /// creates cgroup if it's not created

        /// This code will live here. Life is hard.
        /// setup pipes
        int errorPipes[2];
        if (pipe(errorPipes) < 0)
            Die("pipe: %m");

        /// close errorPipes when clone ends
        for (int i = 0; i < 2; i++)
            if (fcntl(errorPipes[i], F_SETFD, fcntl(errorPipes[i], F_GETFD) | FD_CLOEXEC) < 0 ||
                fcntl(errorPipes[i], F_SETFL, fcntl(errorPipes[i], F_GETFL) | O_NONBLOCK) < 0)
                Die("fcntl on pipe: %m");

        /// sanity check
        if (isolatedProcessStack == nullptr) {
            Die("Must provide a pointer to stack if the jailer is used as a library.");
        }

        int processPid =
            clone(ProcessInitialiser::ASyncStart,  /// Function to execute as the body of the new process
                  isolatedProcessStack,            /// stack for the new process (argv is the start of stack)
                  SIGCHLD | CLONE_NEWIPC | (config.shareNetwork ? 0 : CLONE_NEWNET) | CLONE_NEWNS | CLONE_NEWPID,
                  new ProcessInitialiser(config, uid, gid, errorPipes));  /// pass config for initialiser

        if (processPid < 0) {
            Die("clone: %m");
        }

        if (!processPid) {
            Die("clone returned 0");
        }

        Msg("Start waiting for process\n");

        ProcessKeeper keeper(config, processPid, errorPipes);
        RunStats finalStats = keeper.startKeeper();
        PrintStats(finalStats);
    }
};

int Jailer::firstProcessUid = 50000;
int Jailer::firstProcessGid = 50000;
int Jailer::firstCgroupId = 1000;
int Jailer::maxProcessesPerCG = 10;
string Jailer::baseBoxDir = "/tmp/box";
