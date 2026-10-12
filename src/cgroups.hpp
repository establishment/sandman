#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>

#include "die.hpp"
#include "runstats.hpp"

#include "cpp-base/string_utils.hpp"

using std::string;

/// One cgroup v2 control group per jail, under the unified hierarchy's root
class CGroups {
  public:
    static inline string cgRootPath = "/sys/fs/cgroup";
    static const int kLeftoverWaitMs = 10000;

    string cgName;
    int cgMemoryLimitKB = 0;  /// 0 for none
    int cgMaxProcesses = 0;   /// cap on the processes and threads in it, 0 for none

  protected:
    string getPath(const string& parameter) {
        return Base::StrCat(cgRootPath, '/', cgName, '/', parameter);
    }

    string readStat(const string& parameter) {
        string path = getPath(parameter);
        int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            Base::Die("Cannot open %s: %m", path.c_str());
        }
        char buffer[4096];
        ssize_t size = read(fd, buffer, sizeof(buffer));
        close(fd);
        if (size < 0) {
            Base::Die("Cannot read %s: %m", path.c_str());
        }
        if (size == sizeof(buffer)) {
            Base::Die("Attribute %s too long", path.c_str());
        }
        string value(buffer, size);
        if (!value.empty() && value.back() == '\n') {
            value.pop_back();
        }
        Base::Msg(2, "CG: Read '%s' = '%s'\n", parameter.c_str(), value.c_str());
        return value;
    }

    /// A parameter the kernel may lack, like swap accounting, is written only if present
    void writeStat(const string& parameter, const string& value, bool maybe = false) {
        string path = getPath(parameter);
        Base::Msg(2, "CG: Write %s = %s\n", parameter.c_str(), value.c_str());
        int fd = open(path.c_str(), O_WRONLY | O_TRUNC | O_CLOEXEC);
        if (fd < 0) {
            if (maybe) {
                Base::Msg(2, "No %s to write\n", path.c_str());
                return;
            }
            Base::Die("Cannot open %s: %m", path.c_str());
        }
        ssize_t written = write(fd, value.c_str(), value.size());
        close(fd);
        if (written != (ssize_t)value.size()) {
            Base::Die("%s: %m", Base::StrCat("Cannot set ", path, " to ", value).c_str());
        }
    }

    bool populated() {
        return readStat("cgroup.events").find("populated 1") != string::npos;
    }

    bool exists() {
        struct stat st;
        return stat(Base::StrCat(cgRootPath, '/', cgName).c_str(), &st) == 0;
    }

    /// A run never shares its control group with what an earlier one left behind, as when its keeper was killed
    void remove() {
        kill();
        for (int waitedMs = 0; populated(); waitedMs += 1) {
            if (waitedMs == kLeftoverWaitMs) {
                Base::Die("Processes left in control group %s outlived cgroup.kill", cgName.c_str());
            }
            usleep(1000);
        }
        string path = Base::StrCat(cgRootPath, '/', cgName);
        if (rmdir(path.c_str()) < 0) {
            Base::Die("Cannot remove control group %s: %m", path.c_str());
        }
    }

    static unsigned long long statLine(const string& stat, const string& key) {
        size_t at = stat.find(key);
        if (at == string::npos) {
            Base::Die("No %s in cpu.stat", key.c_str());
        }
        return strtoull(stat.c_str() + at + key.size(), nullptr, 10);
    }

  public:
    void init(int cgId) {
        cgName = Base::StrCat("box-", cgId);
        Base::Msg("Using control group %s\n", cgName.c_str());
    }

    /// A fresh control group, with its controllers enabled at the root
    void prepare() {
        Base::Msg("Preparing control group %s\n", cgName.c_str());
        if (exists()) {
            remove();
        }
        string path = Base::StrCat(cgRootPath, '/', cgName);
        if (mkdir(path.c_str(), 0755) < 0) {
            Base::Die("Failed to create control group %s: %m", path.c_str());
        }
        string controllers = Base::StrCat(cgRootPath, "/cgroup.subtree_control");
        int fd = open(controllers.c_str(), O_WRONLY | O_CLOEXEC);
        if (fd < 0 || write(fd, "+memory +pids", 13) != 13) {
            Base::Die("Cannot enable the memory and pids controllers: %m");
        }
        close(fd);
    }

    void applyLimits() {
        if (cgMemoryLimitKB) {
            string bytes = Base::StrCat((unsigned long long)cgMemoryLimitKB * 1024);
            writeStat("memory.max", bytes);
            /// No swap: the limit is on memory, and a program paging through swap would hide behind the CPU clock
            writeStat("memory.swap.max", "0", true);
            /// An out-of-memory kill takes the whole group, not just the biggest of a program's processes
            writeStat("memory.oom.group", "1");
        }
        /// Counted for the whole tree, which RLIMIT_NPROC's per-uid count is not
        if (cgMaxProcesses) {
            writeStat("pids.max", Base::StrCat(cgMaxProcesses));
        }
    }

    /// Opened before the jail hides /sys, so a process can enter from inside it
    int openProcs() {
        string path = getPath("cgroup.procs");
        int fd = open(path.c_str(), O_WRONLY | O_CLOEXEC);
        if (fd < 0) {
            Base::Die("Cannot open %s: %m", path.c_str());
        }
        return fd;
    }

    void kill() {
        writeStat("cgroup.kill", "1");
    }

    void cleanup() {
        if (!exists()) {
            Base::Msg("Control group %s not found, there isn't anything to clean up\n", cgName.c_str());
            return;
        }
        remove();
    }

    RunStats::TimeStat cpuTimes() {
        string stat = readStat("cpu.stat");
        RunStats::TimeStat timeStat;
        timeStat.cpuTimeNs = statLine(stat, "usage_usec ") * 1000;
        timeStat.userTimeNs = statLine(stat, "user_usec ") * 1000;
        timeStat.systemTimeNs = statLine(stat, "system_usec ") * 1000;
        return timeStat;
    }

    size_t memoryKB() {
        return strtoull(readStat("memory.peak").c_str(), nullptr, 10) >> 10;
    }
};
