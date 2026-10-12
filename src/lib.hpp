#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/close_range.h>
#include <linux/landlock.h>
#ifndef LANDLOCK_ACCESS_FS_REFER  /// Headers older than the 5.19 kernel this needs
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif
#include <linux/openat2.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>

#include <map>
#include <string>
#include <vector>

#include "cgroups.hpp"
#include "config.hpp"
#include "die.hpp"
#include "json/json.cpp"
#include "rules.hpp"
#include "runstats_json_impl.hpp"

#include "cpp-base/os.hpp"
#include "cpp-base/string_utils.hpp"

using std::string;
using std::vector;
using std::pair;

using Base::Msg;
using Base::Die;

CGroups cg;
bool inKeeper = true;  /// cleared in the box's copy of the process, so only the keeper writes the meta file

class ProcessKeeper {
  public:
    ProcessKeeper(ProcessConfig config, int pid, int errorPipes[2]);

    ProcessConfig config;  /// time limits and such
    int processPid;        /// pid of the isolate process (initially cloned, than execved)
    int errorPipes[2];     /// the box writes its errors to errorPipes[1], the keeper reads errorPipes[0]

    /// The wall clock, from the exec of the program; monotonic, so a clock step can't shorten or lengthen a run
    struct timespec wallStart;

    void startWallClock() {
        clock_gettime(CLOCK_MONOTONIC, &wallStart);
    }

    unsigned long long wallTimeNs() {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        return (now.tv_sec - wallStart.tv_sec) * 1000000000ull + now.tv_nsec - wallStart.tv_nsec;
    }

    RunStats processStats;  /// keeps process data in case it was killed by TLE
    string childError;      /// what Die in the box sent, verbatim, for the log
    bool programStarted = false;  /// set at the exec, before which the limits are the setup's

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
        }
    }

    /// get stats about process
  protected:
    unsigned long long getProcTimeMs() { return cg.cpuTimeMs(); }

    unsigned long long getWallTimeMs() { return wallTimeNs() / 1000000; }

    int getMemoryKB() { return cg.memoryKB(); }

    void updateStats() {
        processStats.update(cg.getFullTime());
        processStats.timeStat.wallTimeNs = wallTimeNs();
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
        /// Until the exec, only the wall clock runs, against the jail's setup rather than the program
        if (!programStarted) {
            if (config.wallTimeLimitMs && getWallTimeMs() >= config.wallTimeLimitMs + config.extraTimeMs) {
                return RunStats::INTERNAL_ERROR;
            }
            return RunStats::OK;
        }

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

    /// Die in the box sends its whole log entry, of which the message, with its quotes escaped, is what the result can use
    static string childErrorMessage(const string& error) {
        const string key = "{\"message\":\"";
        if (error.compare(0, key.size(), key) != 0) {
            return error;
        }
        string message;
        for (size_t i = key.size(); i < error.size() && error[i] != '"'; i += 1) {
            if (error[i] == '\\' && i + 1 < error.size()) {
                i += 1;
            }
            message += (unsigned char)error[i] < ' ' ? ' ' : error[i];
        }
        while (!message.empty() && message.back() == ' ') {
            message.pop_back();
        }
        return message;
    }

    /// Waits for the program's exec, when the close-on-exec error pipe hangs up (or carries the child's error)
    void waitForExec() {
        struct pollfd errorPipe = {errorPipes[0], POLLIN, 0};
        while (!processStats.processWasKilled) {
            int ready = poll(&errorPipe, 1, -1);
            if (ready > 0) {
                return;
            }
            if (ready < 0 && errno != EINTR) {
                Die("poll: %m");
            }
        }
    }

  public:
    RunStats startKeeper() {
        startWallClock();

        /// switch error pipes fd to read errors from the child process in which the
        /// process runs
        close(errorPipes[1]);

        mockSignals();

        /// if checkIntervalMs is not null, status check is on
        if (config.checkIntervalMs) {
            startStatusCheck(config.checkIntervalMs);
        }

        waitForExec();
        if (processStats.processWasKilled) {
            return processStats;
        }
        programStarted = true;
        startWallClock();

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

            /// An error from inside the box is the run's result, so it reaches the meta file before the jail dies of it
            char interr[Base::kDieBufferSize];
            int n = read(errorPipes[0], interr, sizeof(interr) - 1);
            if (n > 0) {
                interr[n] = 0;
                childError = interr;
                processStats.resultCode = RunStats::INTERNAL_ERROR;
                processStats.internalMessage = childErrorMessage(childError);
                return processStats;
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
    if (status == RunStats::INTERNAL_ERROR) {
        processKeeper->killProcess(status, "The jail's setup outlasted the wall time limit");
    } else if (status != RunStats::OK) {
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
    ProcessInitialiser(ProcessConfig config, int uid, int gid, int errorPipes[2], int cgroupProcsFd) {
        this->config = config;
        this->uid = uid;
        this->gid = gid;
        this->errorPipes[0] = errorPipes[0];
        this->errorPipes[1] = errorPipes[1];
        this->cgroupProcsFd = cgroupProcsFd;
    }

    ProcessConfig config;
    int uid;
    int gid;
    int errorPipes[2];
    int cgroupProcsFd;

    /// sets up everything so that the process will be run in a controlled
    /// sandbox as specified by the config given
    void setupSystem() {
        Base::die_fd = errorPipes[1];
        close(errorPipes[0]);

        /// Taken before the chroot hides the box's parent
        int boxParentFd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (boxParentFd < 0) {
            Die("open box dir: %m");
        }

        setupRoot();
        setupPipes();
        setupFilePermissions(boxParentFd);
        setupRlimits();
        forbidSymlinks();

        /// changes dir before executin to dir provided from flag / set dir
        if (config.execDirectory.size() && chdir(config.execDirectory.c_str())) {
            Die("chdir: %m");
        }
    }

    /// Everything from the cgroup entry on is billed to the program, so it comes last, with the exec's inputs ready
    void execProgram() {
        char** argv = Base::StringToCharSS(Base::ParseCommandLine(config.runCommand));
        environ = Rules::Environment(config.environment).getEnvironment();

        if (write(cgroupProcsFd, "0", 1) != 1) {
            Die("cgroup.procs: %m");
        }
        close(cgroupProcsFd);
        setupCredentials();
        /// The program gets its three standard files and nothing else of the jail's; the error pipe hanging up at
        /// the exec is also what starts its wall clock
        if (syscall(SYS_close_range, 3, ~0U, CLOSE_RANGE_CLOEXEC) < 0) {
            Die("close_range: %m");
        }
        execvp(argv[0], argv);
        Die("execvp(%s): %m", argv[0]);
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
        /// Dies with its keeper, which alone enforces the limits. Set after the uid change, which clears it
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0) {
            Die("prctl: %m");
        }
        setpgrp();
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

        Base::MakeDir("/tmp", 0777);
        /// mkdir's mode is masked by the umask
        if (chmod("/tmp", 0777) < 0) {
            Die("chmod /tmp: %m");
        }
    }

    /// apply permissions for the process uid
    /// std{in,out,err} permissions and auto binary exec permission and custom permissions
    /// uses setfacl(/usr/bin/setfacl)[apt install -acl]
    void setupFilePermissions(int lockFd) {
        Rules::FilePermissions filePermissions(config.filePermissions);
        filePermissions.applyRules(uid, lockFd);
    }

    /// Nothing in a box may be a symlink, since root later opens files there by name
    void forbidSymlinks() {
        struct landlock_ruleset_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.handled_access_fs = LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER;
        int ruleset = syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0);
        if (ruleset < 0) {
            Die("landlock_create_ruleset (needs Linux 5.19 with landlock in its lsm list): %m");
        }

        /// Handled only to be granted everywhere: under a ruleset, moving a file between directories is refused otherwise
        struct landlock_path_beneath_attr everywhere;
        memset(&everywhere, 0, sizeof(everywhere));
        everywhere.allowed_access = LANDLOCK_ACCESS_FS_REFER;
        everywhere.parent_fd = open("/", O_PATH | O_CLOEXEC);
        if (everywhere.parent_fd < 0 || syscall(SYS_landlock_add_rule, ruleset, LANDLOCK_RULE_PATH_BENEATH, &everywhere, 0) < 0) {
            Die("landlock_add_rule: %m");
        }
        close(everywhere.parent_fd);

        if (syscall(SYS_landlock_restrict_self, ruleset, 0) < 0) {
            Die("landlock_restrict_self: %m");
        }
        close(ruleset);
    }

    /// Opened as root under a name the program could have reused, so no component of it may be a link
    void openRedirect(const string& path, uint64_t flags, uint64_t mode, int targetFd) {
        struct open_how how;
        memset(&how, 0, sizeof(how));
        how.flags = flags;
        how.mode = mode;
        how.resolve = RESOLVE_NO_SYMLINKS;
        close(targetFd);
        if (syscall(SYS_openat2, AT_FDCWD, path.c_str(), &how, sizeof(how)) != targetFd) {
            Die("open(\"%s\"): %m", path.c_str());
        }
    }

    /// redirect std{in,out,err}
    void setupPipes() {
        auto openStdin = [&]() {
            if (config.redirectStdin.size()) {
                openRedirect(config.redirectStdin, O_RDONLY, 0, 0);
            }
        };
        auto openStdout = [&]() {
            if (config.redirectStdout.size()) {
                openRedirect(config.redirectStdout, O_WRONLY | O_CREAT | O_TRUNC, 0666, 1);
            }
        };

        if (config.swapPipeOpenOrder) {
            openStdout();
            openStdin();
        } else {
            openStdin();
            openStdout();
        }

        if (config.redirectStderr.size()) {
            openRedirect(config.redirectStderr, O_WRONLY | O_CREAT | O_TRUNC, 0666, 2);
        } else {
            dup2(1, 2);
        }
    }

    string getRlimitName(int resource) {
        static std::map<int, string> resource_name = {
            {RLIMIT_AS, "RLIMIT_AS"},         {RLIMIT_FSIZE, "RLIMIT_FSIZE"},     {RLIMIT_STACK, "RLIMIT_STACK"},
            {RLIMIT_NOFILE, "RLIMIT_NOFILE"}, {RLIMIT_MEMLOCK, "RLIMIT_MEMLOCK"}, {RLIMIT_NPROC, "RLIMIT_NPROC"},
        };

        return resource_name[resource];
    }

    void setRlimit(int resource, rlim_t limit) {
        struct rlimit rl;
        bzero(&rl, sizeof(rl));
        rl.rlim_cur = limit;
        rl.rlim_max = limit;

        if (setrlimit(resource, &rl) < 0) {
            Die("%s: %m", Base::StrCat("setrlimit(", getRlimitName(resource), ", ", limit, ")").c_str());
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
    inKeeper = false;
    ProcessInitialiser* initialiser = (ProcessInitialiser*)args;
    initialiser->setupSystem();

    /// child process inherits everything from parent
    /// * opened std{in,out,err}
    /// * cpu, mem, disk, network limits
    /// * cgroup id (associated with limits)
    /// * pwd, relative root
    /// all these limitations can't be enlarged, only reduced/shrinked
    initialiser->execProgram();

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
    bool statsPrinted = false;
    static Jailer* running;

    Jailer(const ProcessConfig& config, void* isolatedProcessStack = nullptr)
          : config(config), isolatedProcessStack(isolatedProcessStack) {
        /// sanity check
        if (config.boxId == -1) {
            Die("Specify box-id.");
        }

        if (config.processId < 0 or config.processId >= maxProcessesPerCG) {
            Die("Process if out of range [0, %d). Id=%d", maxProcessesPerCG, config.processId);
        }

        uid = firstProcessUid + maxProcessesPerCG * config.boxId + config.processId;  /// Sandman.load_compile_cache computes it too
        gid = firstProcessGid + maxProcessesPerCG * config.boxId + config.processId;
        cgid = firstCgroupId + maxProcessesPerCG * config.boxId + config.processId;

        boxDir = Base::StrCat(baseBoxDir, "/", config.boxId);
        this->meta_fd = -1;
    }

    ~Jailer() { close(meta_fd); }

    void PrintStats(const RunStats& stats) {
        if (meta_fd != -1) {
            string stats_str = AutoJson::Json(stats).Stringify(false);

            Base::xwrite(meta_fd, stats_str.c_str(), stats_str.size());
        }
        statsPrinted = true;
    }

    /// Die exits without a word in the meta file, and an empty one tells the evaluator nothing about why
    static void PrintErrorStatsAtExit() {
        if (inKeeper && running != nullptr && !running->statsPrinted) {
            running->WriteErrorStats();
        }
    }

    void BoxInit() {
        umask(0027);  // new files will be created with 0750

        if (config.metaFile.size()) {
            meta_fd = open(config.metaFile.c_str(), O_WRONLY | O_TRUNC | O_CREAT | O_CLOEXEC, 0644);
        }

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
        running = this;
        atexit(PrintErrorStatsAtExit);

        if (!Base::DirExists("box")) {
            Die("Box directory not found, did you run 'isolate --init'?");
        }

        cg.prepare();  /// creates cgroup if it's not created
        cg.applyLimits();
        int cgroupProcsFd = cg.openProcs();

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

        /// TODO: the program is its PID namespace's init, which drops signals it raises itself, so abort() ends as SIGSEGV
        int processPid =
            clone(ProcessInitialiser::ASyncStart,  /// Function to execute as the body of the new process
                  isolatedProcessStack,            /// stack for the new process (argv is the start of stack)
                  SIGCHLD | CLONE_NEWIPC | (config.shareNetwork ? 0 : CLONE_NEWNET) | CLONE_NEWNS | CLONE_NEWPID,
                  new ProcessInitialiser(config, uid, gid, errorPipes, cgroupProcsFd));  /// pass config for initialiser

        if (processPid < 0) {
            Die("clone: %m");
        }
        close(cgroupProcsFd);

        if (!processPid) {
            Die("clone returned 0");
        }

        Msg("Start waiting for process\n");

        ProcessKeeper keeper(config, processPid, errorPipes);
        RunStats finalStats = keeper.startKeeper();
        PrintStats(finalStats);
        if (finalStats.resultCode == RunStats::INTERNAL_ERROR) {
            const string& error = keeper.childError.empty() ? finalStats.internalMessage : keeper.childError;
            bool wholeEntry = error.size() > 1 && error[0] == '{' && error[error.find_last_not_of('\n')] == '}';
            Die("childErrors", error.c_str(), wholeEntry);
        }
    }
};

Jailer* Jailer::running = nullptr;
int Jailer::firstProcessUid = 50000;
int Jailer::firstProcessGid = 50000;
int Jailer::firstCgroupId = 1000;
int Jailer::maxProcessesPerCG = 10;
string Jailer::baseBoxDir = "/tmp/box";
