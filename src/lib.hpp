#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/audit.h>
#include <linux/close_range.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
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
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>

#include <algorithm>
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

using Base::Msg;
using Base::Die;

CGroups cg;

/// Through the pidfd rather than the pid, which another process may have inherited once the jail was reaped
void killByFd(int pidFd) {
    syscall(SYS_pidfd_send_signal, pidFd, SIGKILL, NULL, 0);
}

/// An output stream the keeper carries from a pipe into its file, so the written pages are never the program's memory
struct Relay {
    int pipeRead = -1;   /// the keeper's end, -1 once the stream ended
    int pipeWrite = -1;  /// the program's end, which the keeper closes after the clone
    int fileFd = -1;
    unsigned long long bytes = 0;
};

/// Die in the box sends its whole log entry, of which the message, with its quotes escaped, is what the result can use
string dieEntryMessage(const string& entry) {
    const string key = "{\"message\":\"";
    if (entry.compare(0, key.size(), key) != 0) {
        return entry;
    }
    string message;
    for (size_t i = key.size(); i < entry.size() && entry[i] != '"'; i += 1) {
        if (entry[i] == '\\' && i + 1 < entry.size()) {
            i += 1;
        }
        message += (unsigned char)entry[i] < ' ' ? ' ' : entry[i];
    }
    while (!message.empty() && message.back() == ' ') {
        message.pop_back();
    }
    return message;
}

/// Watches the jailed process from outside: the limits, and what it ended as
class ProcessKeeper {
  public:
    static const int kCheckIntervalMs = 100;  /// how often the limits are checked, whatever the program's output does
    static const unsigned long long kDrainBudget = 8 << 20;  /// output moved per check of the limits

    ProcessConfig config;
    int processPid;
    int pidFd;      /// readable once the process is gone, so a poll sees its end at once
    int errorPipe;  /// the box's Die writes here; close-on-exec, so it hangs up when the program starts
    Relay* relays;  /// stdout and stderr, where they go to files
    struct timespec* execClock;  /// written by the box right before the exec, on a page both sides share

    /// The wall clock, from the exec of the program; monotonic, so a clock step can't shorten or lengthen a run
    struct timespec wallStart;
    bool programStarted = false;  /// set at the exec, before which the limits are the setup's
    RunStats stats;
    string childError;  /// what Die in the box sent, verbatim, for the log

    ProcessKeeper(const ProcessConfig& config, int processPid, int pidFd, int errorPipe, Relay* relays, struct timespec* execClock)
            : config(config), processPid(processPid), pidFd(pidFd), errorPipe(errorPipe), relays(relays), execClock(execClock) {}

    void startWallClock() {
        clock_gettime(CLOCK_MONOTONIC, &wallStart);
    }

    unsigned long long wallTimeNs() {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        return (now.tv_sec - wallStart.tv_sec) * 1000000000ull + now.tv_nsec - wallStart.tv_nsec;
    }

    void updateStats() {
        stats.timeStat = cg.cpuTimes();
        stats.timeStat.wallTimeNs = wallTimeNs();
        stats.memoryKB = cg.memoryKB();
    }

    RunStats::ResultCode checkLimits() {
        /// Until the exec, only the wall clock runs, against the jail's setup rather than the program
        if (!programStarted) {
            if (config.wallTimeLimitMs && wallTimeNs() / 1000000 >= config.wallTimeLimitMs) {
                return RunStats::INTERNAL_ERROR;
            }
            return RunStats::OK;
        }
        if (config.cpuTimeLimitMs && cg.cpuTimes().cpuTimeNs / 1000000 >= config.cpuTimeLimitMs) {
            return RunStats::TIME_LIMIT_EXCEEDED;
        }
        if (config.wallTimeLimitMs && wallTimeNs() / 1000000 >= config.wallTimeLimitMs) {
            return RunStats::WALL_TIME_LIMIT_EXCEEDED;
        }
        if (config.memoryLimitKB && cg.memoryKB() >= (size_t)config.memoryLimitKB) {
            return RunStats::MEMORY_LIMIT_EXCEEDED;
        }
        return RunStats::OK;
    }

    /// The program is its PID namespace's init, and the kernel kills the whole namespace with it
    void killProcess(RunStats::ResultCode reason) {
        killByFd(pidFd);
        stats.processWasKilled = true;
        stats.resultCode = reason;
    }

    /// Moves what the pipe holds into the file, a bounded amount per call so a program that never stops printing
    /// still gets its limits checked; past the output cap the stream is dropped and the run is over
    bool drain(Relay& relay, unsigned long long budget) {
        unsigned long long cap = config.fileSizeLimitKB ? (unsigned long long)config.fileSizeLimitKB * 1024 : ~0ull;
        while (relay.pipeRead >= 0 && budget > 0) {
            if (relay.bytes == cap) {
                struct pollfd more = {relay.pipeRead, POLLIN, 0};
                if (poll(&more, 1, 0) <= 0) {
                    return true;
                }
                /// Anything more is over the cap; a hangup with nothing more is the stream's end
                close(relay.pipeRead);
                relay.pipeRead = -1;
                return !(more.revents & POLLIN);
            }
            unsigned long long chunk = std::min({cap - relay.bytes, budget, 1ull << 20});
            ssize_t moved = splice(relay.pipeRead, NULL, relay.fileFd, NULL, chunk, SPLICE_F_NONBLOCK);
            if (moved > 0) {
                relay.bytes += moved;
                budget -= moved;
            } else if (moved == 0) {
                close(relay.pipeRead);
                relay.pipeRead = -1;
            } else if (errno == EAGAIN) {
                return true;
            } else if (errno != EINTR) {
                Die("splice: %m");
            }
        }
        return true;
    }

    string readChildError() {
        string error;
        char buffer[4096];
        for (ssize_t n; (n = read(errorPipe, buffer, sizeof(buffer))) != 0;) {
            if (n < 0 && errno != EINTR) {
                Die("read error pipe: %m");
            }
            if (n > 0) {
                error.append(buffer, n);
            }
        }
        return error;
    }

    RunStats run() {
        startWallClock();
        struct pollfd fds[4] = {{errorPipe, POLLIN, 0}, {pidFd, POLLIN, 0}, {relays[0].pipeRead, POLLIN, 0}, {relays[1].pipeRead, POLLIN, 0}};
        unsigned long long nextCheckNs = wallTimeNs() + kCheckIntervalMs * 1000000ull;
        while (true) {
            unsigned long long nowNs = wallTimeNs();
            int ready = poll(fds, 4, nowNs < nextCheckNs ? (nextCheckNs - nowNs) / 1000000 + 1 : 0);
            if (ready < 0 && errno != EINTR) {
                Die("poll: %m");
            }
            /// The pipe hanging up is the exec, whose moment the box noted itself; a message on it is a Die, which exits right after
            if (fds[0].revents) {
                programStarted = true;
                if (execClock->tv_sec) {
                    wallStart = *execClock;
                } else {
                    startWallClock();
                }
                fds[0].fd = -1;
            }
            bool overflowed = false;
            for (int i = 0; i < 2; i += 1) {
                if (fds[2 + i].revents) {
                    overflowed |= !drain(relays[i], kDrainBudget);
                    fds[2 + i].fd = relays[i].pipeRead;
                }
            }
            if (overflowed) {
                killProcess(RunStats::OUTPUT_LIMIT_EXCEEDED);
                break;
            }
            if (fds[1].revents) {
                break;
            }
            if (wallTimeNs() < nextCheckNs) {
                continue;
            }
            nextCheckNs += kCheckIntervalMs * 1000000ull;
            RunStats::ResultCode code = checkLimits();
            if (code != RunStats::OK) {
                killProcess(code);
                if (code == RunStats::INTERNAL_ERROR) {
                    stats.internalMessage = "The jail's setup outlasted the wall time limit";
                }
                break;
            }
        }

        int status;
        while (waitpid(processPid, &status, 0) < 0) {
            if (errno != EINTR) {
                Die("waitpid: %m");
            }
        }

        /// Every writer is dead with the program (its PID namespace goes with it), so the pipes drain to their end
        bool overflowed = false;
        for (int i = 0; i < 2; i += 1) {
            overflowed |= !drain(relays[i], ~0ull);
        }

        /// An error from inside the box is the run's result, so it reaches the meta file before the jail dies of it
        childError = readChildError();
        if (!childError.empty()) {
            stats.resultCode = RunStats::INTERNAL_ERROR;
            stats.internalMessage = dieEntryMessage(childError);
            return stats;
        }

        updateStats();
        if (stats.processWasKilled) {
            return stats;
        }
        if (overflowed) {
            stats.resultCode = RunStats::OUTPUT_LIMIT_EXCEEDED;
            return stats;
        }
        Msg("ProcessStatus:%d\n", status);
        if (WIFEXITED(status)) {
            stats.exitCode = WEXITSTATUS(status);
            stats.resultCode = stats.exitCode ? RunStats::NON_ZERO_EXIT_STATUS : RunStats::OK;
        } else if (WIFSIGNALED(status)) {
            stats.terminalSignal = WTERMSIG(status);
            stats.resultCode = RunStats::RUNTIME_ERROR;
            /// The control group is entered right before the exec, so a death that left it empty was the setup's
            if (stats.memoryKB == 0) {
                stats.resultCode = RunStats::INTERNAL_ERROR;
                stats.internalMessage = Base::StrCat("The jail's setup died with signal ", stats.terminalSignal);
            }
        } else {
            Die("waitpid: unknown status %x, giving up!", status);
        }

        RunStats::ResultCode code = checkLimits();
        if (code != RunStats::OK) {
            stats.resultCode = code;
        }
        return stats;
    }
};

/// The box's side: the jail is built as root, then the program takes its place
class ProcessInitialiser {
  public:
    static int ASyncStart(void*);

    ProcessInitialiser(const ProcessConfig& config, int uid, int gid, int errorPipes[2], int cgroupProcsFd, Relay* relays,
                       struct timespec* execClock)
            : config(config), uid(uid), gid(gid), errorPipe(errorPipes[1]), keeperPipe(errorPipes[0]),
              cgroupProcsFd(cgroupProcsFd), stdoutFd(relays[0].pipeWrite), stderrFd(relays[1].pipeWrite), execClock(execClock) {}

    ProcessConfig config;
    int uid;
    int gid;
    int errorPipe;
    int keeperPipe;
    int cgroupProcsFd;
    int stdoutFd;  /// the keeper's relay for stdout, or -1 to open the redirect here
    int stderrFd;
    struct timespec* execClock;  /// where the keeper reads the program's start from

    /// Dies with its keeper, which alone enforces the limits; a uid change clears it, so it is set again after
    void dieWithKeeper() {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0) {
            Die("prctl: %m");
        }
    }

    void setupSystem() {
        Base::die_fd = errorPipe;
        close(keeperPipe);

        /// Taken before the chroot hides the box's parent
        int boxParentFd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (boxParentFd < 0) {
            Die("open box dir: %m");
        }

        setupRoot();
        setupPipes();
        Rules::FilePermissions(config.permissionRules).applyRules(uid, boxParentFd);
        setupRlimits();
        forbidSymlinks();

        if (config.execDirectory.size() && chdir(config.execDirectory.c_str())) {
            Die("chdir: %m");
        }
    }

    /// Everything from the cgroup entry on is billed to the program, so it comes last, with the exec's inputs ready
    void execProgram() {
        char** argv = Base::StringToCharSS(config.runCommand);
        environ = Rules::Environment(config.environmentRules).getEnvironment();

        if (write(cgroupProcsFd, "0", 1) != 1) {
            Die("cgroup.procs: %m");
        }
        close(cgroupProcsFd);
        denySyscalls();
        setupCredentials();
        /// The program gets its three standard files and nothing else of the jail's; the error pipe's hangup marks the exec
        if (syscall(SYS_close_range, 3, ~0U, CLOSE_RANGE_CLOEXEC) < 0) {
            Die("close_range: %m");
        }
        clock_gettime(CLOCK_MONOTONIC, execClock);
        execvp(argv[0], argv);
        Die("execvp(%s): %m", argv[0]);
    }

    /// Refused: user namespaces (they hand out capabilities), kernel subsystems no solution needs, keys and vsock, which reach
    /// other jails, and resizing a pipe, which would make the keeper wake per page of output
    void denySyscalls() {
        const unsigned CLONE_FLAGS = offsetof(struct seccomp_data, args[0]);
        vector<struct sock_filter> filter = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000, 0, 1),  /// the x32 ABI, with other numbers
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        };
        /// A flag word is inspected after the number, which has to be loaded back afterwards
        auto denyFlag = [&](unsigned nr, unsigned flag) {
            filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 4));
            filter.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, CLONE_FLAGS));
            filter.push_back(BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, flag, 0, 1));
            filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM));
            filter.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)));
        };
        auto denyValue = [&](unsigned nr, unsigned argument, unsigned value) {
            filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 4));
            filter.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (unsigned)(offsetof(struct seccomp_data, args[0]) + argument * sizeof(__u64))));
            filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, value, 0, 1));
            filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM));
            filter.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)));
        };
        auto deny = [&](unsigned nr, unsigned error) {
            filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
            filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | error));
        };
        denyFlag(SYS_unshare, CLONE_NEWUSER);
        denyFlag(SYS_clone, CLONE_NEWUSER);
        denyValue(SYS_socket, 0, AF_VSOCK);
        denyValue(SYS_fcntl, 1, F_SETPIPE_SZ);
        deny(SYS_clone3, ENOSYS);  /// its flags are in a struct the filter can't see; libc falls back to clone
        for (unsigned nr : {SYS_setns, SYS_mount, SYS_umount2, SYS_pivot_root, SYS_open_tree, SYS_move_mount, SYS_fsopen, SYS_fsmount,
                       SYS_mount_setattr, SYS_io_uring_setup, SYS_io_uring_enter, SYS_io_uring_register, SYS_bpf, SYS_userfaultfd,
                       SYS_perf_event_open, SYS_add_key, SYS_request_key, SYS_keyctl, SYS_kexec_load, SYS_kexec_file_load}) {
            deny(nr, EPERM);
        }
        filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

        struct sock_fprog program = {(unsigned short)filter.size(), filter.data()};
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 || syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) < 0) {
            Die("seccomp: %m");
        }
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
        dieWithKeeper();
        /// A session of its own, so the program has no controlling terminal to reach
        if (setsid() < 0) {
            Die("setsid: %m");
        }
    }

  protected:
    /// The jail's root: a private ramdisk with the system's directories bound in, its own /tmp and /dev, and the box
    void setupRoot() {
        /// Our mounts stay inside our namespace, whatever propagation systemd set up
        if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
            Die("Cannot privatize mounts: %m");
        }
        if (mount("none", "root", "tmpfs", 0, "mode=755") < 0) {
            Die("Cannot mount root ramdisk: %m");
        }

        Rules::DirRules(config.includeDirs).applyRules();

        if (chroot("root") < 0) {
            Die("Chroot failed: %m");
        }
        if (chdir("/box") < 0) {
            Die("Cannot change current directory: %m");
        }

        makeWorldWritableDir("/tmp");
        makeDev();
    }

    /// mkdir's mode is masked by the umask
    void makeWorldWritableDir(const char* path) {
        Base::MakeDir(path, 0777);
        if (chmod(path, 01777) < 0) {
            Die("chmod %s: %m", path);
        }
    }

    /// The program's /dev is a few nodes of our own rather than the host's, whose devices it has no business with
    void makeDev() {
        Base::MakeDir("/dev", 0755);
        if (chmod("/dev", 0755) < 0) {
            Die("chmod /dev: %m");
        }
        struct Node { const char* name; int major; int minor; };
        for (Node node : {Node{"null", 1, 3}, Node{"zero", 1, 5}, Node{"full", 1, 7}, Node{"random", 1, 8}, Node{"urandom", 1, 9}, Node{"tty", 5, 0}}) {
            string path = Base::StrCat("/dev/", node.name);
            if (mknod(path.c_str(), S_IFCHR | 0666, makedev(node.major, node.minor)) < 0 || chmod(path.c_str(), 0666) < 0) {
                Die("mknod %s: %m", path.c_str());
            }
        }
        for (auto link : {std::pair<const char*, const char*>{"/dev/fd", "/proc/self/fd"}, {"/dev/stdin", "/proc/self/fd/0"},
                          {"/dev/stdout", "/proc/self/fd/1"}, {"/dev/stderr", "/proc/self/fd/2"}}) {
            if (symlink(link.second, link.first) < 0) {
                Die("symlink %s: %m", link.first);
            }
        }
        makeWorldWritableDir("/dev/shm");
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

    /// Output to a file goes through the keeper's relay; a fifo is opened here, in the order the two sides agreed on
    void setupPipes() {
        auto openStdin = [&]() {
            if (config.redirectStdin.size()) {
                openRedirect(config.redirectStdin, O_RDONLY, 0, 0);
            }
        };
        auto openStdout = [&]() {
            if (stdoutFd >= 0) {
                if (dup2(stdoutFd, 1) < 0) {
                    Die("dup2 stdout: %m");
                }
            } else if (config.redirectStdout.size()) {
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

        if (stderrFd >= 0) {
            if (dup2(stderrFd, 2) < 0) {
                Die("dup2 stderr: %m");
            }
        } else if (config.redirectStderr.size()) {
            openRedirect(config.redirectStderr, O_WRONLY | O_CREAT | O_TRUNC, 0666, 2);
        } else {
            dup2(1, 2);
        }
    }

    void setRlimit(const char* name, int resource, rlim_t limit) {
        struct rlimit rl = {limit, limit};
        if (setrlimit(resource, &rl) < 0) {
            Die("%s: %m", Base::StrCat("setrlimit(", name, ", ", limit, ")").c_str());
        }
    }

    void setupRlimits() {
        if (config.fileSizeLimitKB) {
            setRlimit("RLIMIT_FSIZE", RLIMIT_FSIZE, (rlim_t)config.fileSizeLimitKB * 1024);
        }
        setRlimit("RLIMIT_STACK", RLIMIT_STACK, config.stackLimitKB ? (rlim_t)config.stackLimitKB * 1024 : RLIM_INFINITY);
        setRlimit("RLIMIT_NOFILE", RLIMIT_NOFILE, 64);
        /// Nothing of the program's is pinned in RAM
        setRlimit("RLIMIT_MEMLOCK", RLIMIT_MEMLOCK, 0);
        /// Per uid, a second net under the control group's pids.max
        if (config.maxProcesses) {
            setRlimit("RLIMIT_NPROC", RLIMIT_NPROC, config.maxProcesses);
        }
        /// No core for the host's core_pattern helper, which runs as root per crash: a pipe pattern ignores 0, and 1 refuses it
        setRlimit("RLIMIT_CORE", RLIMIT_CORE, 1);
    }
};

int ProcessInitialiser::ASyncStart(void* args) {
    /// The keeper's exit hook is not for the box's copy of the process
    Base::DieExitFunction = nullptr;
    ProcessInitialiser* initialiser = (ProcessInitialiser*)args;
    initialiser->dieWithKeeper();
    initialiser->setupSystem();
    initialiser->execProgram();
    return 0;
}

/// One invocation: --init, --run or --cleanup on a box
class Jailer {
  public:
    static constexpr int firstProcessUid = 50000;
    static constexpr int firstProcessGid = 50000;
    static constexpr int firstCgroupId = 1000;
    static constexpr int processesPerBox = 10;  /// process ids a box has, each a uid and a control group
    static constexpr const char* baseBoxDir = "/tmp/box";

    ProcessConfig config;
    string boxDir;
    int uid;
    int gid;
    int cgid;
    int metaFd = -1;
    int pidFd = -1;  /// the jail, once cloned

    Jailer(const ProcessConfig& config) : config(config) {
        if (config.processId < 0 || config.processId >= processesPerBox) {
            Die("Process id out of range [0, %d): %d", processesPerBox, config.processId);
        }

        uid = firstProcessUid + processesPerBox * config.boxId + config.processId;  /// Sandman.load_compile_cache computes it too
        gid = firstProcessGid + processesPerBox * config.boxId + config.processId;
        cgid = firstCgroupId + processesPerBox * config.boxId + config.processId;

        boxDir = Base::StrCat(baseBoxDir, "/", config.boxId);
    }

    void PrintStats(const RunStats& stats) {
        if (metaFd != -1) {
            string statsStr = AutoJson::Json(stats).Stringify(false);
            Base::xwrite(metaFd, statsStr.c_str(), statsStr.size());
        }
    }

    void BoxInit() {
        umask(0027);  /// new files will be created with 0750

        if (config.metaFile.size()) {
            metaFd = open(config.metaFile.c_str(), O_WRONLY | O_TRUNC | O_CREAT | O_CLOEXEC, 0644);
            if (metaFd < 0) {
                Die("open meta file %s: %m", config.metaFile.c_str());
            }
        }

        Base::MakeDir(boxDir);
        if (chdir(boxDir.c_str()) < 0) {
            Die("chdir(%s): %m", boxDir.c_str());
        }

        cg.init(cgid);
        cg.cgMemoryLimitKB = config.memoryLimitKB;
        cg.cgMaxProcesses = config.maxProcesses;
    }

    void Start() {
        Base::verbose_level = config.verboseLevel;

        BoxInit();
        switch (config.mode) {
            case ProcessConfig::kInit:
                Init();
                break;
            case ProcessConfig::kRun:
                Run();
                break;
            case ProcessConfig::kCleanup:
                Cleanup();
                break;
            case ProcessConfig::kUnspecified:
                Die("Specify a mode for isolate");
        }
    }

    void Init() {
        Msg("Preparing sandbox directory\n");
        Base::RMTree("box");
        Base::MakeDir("box", 0750);
        /// Made here rather than by the jails, two of which may otherwise race to make it
        Base::MakeDir("root", 0750);

        cg.prepare();

        Rules::DiskQuota::apply(config.quotaBlocksKB, config.quotaInodes, firstProcessUid + processesPerBox * config.boxId, processesPerBox);
    }

    void Cleanup() {
        if (!Base::DirExists("box")) {
            Msg("Box directory not found, there isn't anything to clean up\n");
        } else {
            Msg("Deleting sandbox directory\n");
            Base::RMTree(boxDir.c_str());
        }

        cg.cleanup();
    }

    /// A redirect to a file is opened here and fed by a pipe, so the output never counts as the program's memory;
    /// a fifo, as interactive runs and games use, is the program's to open
    Relay openRelay(int boxFd, const string& path) {
        Relay relay;
        struct stat st;
        if (path.empty() || (fstatat(boxFd, path.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISFIFO(st.st_mode))) {
            return relay;
        }
        struct open_how how;
        memset(&how, 0, sizeof(how));
        how.flags = O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;
        how.mode = 0666;
        how.resolve = RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH;
        relay.fileFd = syscall(SYS_openat2, boxFd, path.c_str(), &how, sizeof(how));
        if (relay.fileFd < 0) {
            Die("open(\"%s\"): %m", path.c_str());
        }
        /// A fifo put under the name meanwhile opens at once, and is no file to write to
        if (fstat(relay.fileFd, &st) < 0 || !S_ISREG(st.st_mode)) {
            Die("%s is not a regular file", path.c_str());
        }
        int pipeFds[2];
        if (pipe2(pipeFds, O_CLOEXEC) < 0) {
            Die("pipe: %m");
        }
        fcntl(pipeFds[1], F_SETPIPE_SZ, 1 << 20);
        relay.pipeRead = pipeFds[0];
        relay.pipeWrite = pipeFds[1];
        return relay;
    }

    void Run() {
        Msg("Start running\n");

        /// Dying of an error of our own still leaves a result, with the error as its message, and no program behind
        Base::DieExitFunction = [this](std::string entry) {
            if (pidFd >= 0) {
                killByFd(pidFd);
            }
            RunStats errorStats;
            errorStats.internalMessage = dieEntryMessage(entry);
            PrintStats(errorStats);
        };

        if (!Base::DirExists("box")) {
            Die("Box directory not found, did you run 'isolate --init'?");
        }

        cg.prepare();
        cg.applyLimits();
        int cgroupProcsFd = cg.openProcs();

        int errorPipes[2];
        if (pipe2(errorPipes, O_CLOEXEC) < 0) {
            Die("pipe: %m");
        }

        int boxFd = open("box", O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (boxFd < 0) {
            Die("open box: %m");
        }
        Relay relays[2] = {openRelay(boxFd, config.redirectStdout), openRelay(boxFd, config.redirectStderr)};
        close(boxFd);

        /// The exec's moment is the box's to note, since on one CPU the keeper may not run for a while after it
        struct timespec* execClock = (struct timespec*)mmap(NULL, sizeof(*execClock), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (execClock == MAP_FAILED) {
            Die("mmap: %m");
        }

        /// The box is a copy of this process, so its stack can be anywhere of ours
        static char boxStack[1 << 20];
        ProcessInitialiser initialiser(config, uid, gid, errorPipes, cgroupProcsFd, relays, execClock);
        /// TODO: the program is its PID namespace's init, which drops signals it raises itself, so abort() ends as SIGSEGV
        int processPid = clone(ProcessInitialiser::ASyncStart, boxStack + sizeof(boxStack),
                               SIGCHLD | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWPID, &initialiser);
        if (processPid < 0) {
            Die("clone: %m");
        }
        pidFd = syscall(SYS_pidfd_open, processPid, 0);
        if (pidFd < 0) {
            Die("pidfd_open: %m");
        }
        close(cgroupProcsFd);
        close(errorPipes[1]);
        for (Relay& relay : relays) {
            if (relay.pipeWrite >= 0) {
                close(relay.pipeWrite);
            }
        }

        Msg("Start waiting for process\n");
        ProcessKeeper keeper(config, processPid, pidFd, errorPipes[0], relays, execClock);
        RunStats finalStats = keeper.run();
        PrintStats(finalStats);
        Base::DieExitFunction = nullptr;
        if (finalStats.resultCode == RunStats::INTERNAL_ERROR) {
            const string& error = keeper.childError.empty() ? finalStats.internalMessage : keeper.childError;
            bool wholeEntry = error.size() > 1 && error[0] == '{' && error[error.find_last_not_of('\n')] == '}';
            Die("childErrors", error.c_str(), wholeEntry);
        }
    }
};
