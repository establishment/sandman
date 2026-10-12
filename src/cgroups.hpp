#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#include <string>
#include <vector>

#include "die.hpp"
#include "runstats.hpp"

#include "cpp-base/string_utils.hpp"
#include "cpp-base/os.hpp"

/// CGroups v2 API - simplified for unified hierarchy
class CGroups {
  public:
    static inline string cgRootPath = "/sys/fs/cgroup";

    CGroups() {
        this->cgName = "";
        this->cgMemoryLimitKB = 0;
    }

    string cgName;         /// name of the control group
    int cgMemoryLimitKB;        /// memory limit for that cg

    static const int kCGBufferSize = 4096;
    char buffer[kCGBufferSize];

    static const int kLeftoverWaitMs = 10000;

  protected:
    /// Build path to cgroup v2 file: /sys/fs/cgroup/group_name/parameter
    string getPath(const string& parameter) {
        return Base::StrCat(cgRootPath, '/', cgName, '/', parameter);
    }

    int readStat(const string& parameter, bool maybe=false) {
        int success = 0;
        int readSize = 0;

        string path = getPath(parameter);

        int fd = open(path.c_str(), O_RDONLY);
        if (fd < 0) {
            if (maybe) {
                goto fail;
            }
            Base::Die("Cannot read %s: %m", path.c_str());
        }

        readSize = read(fd, buffer, kCGBufferSize);

        /// check read
        if (readSize < 0) {
            if (maybe) {
                goto fail_close;
            }
            Base::Die("Cannot read %s: %m", path.c_str());
        }

        if (readSize >= kCGBufferSize - 1) {
            Base::Die("Attribute %s too long", path.c_str());
        }

        /// erase \n from answer
        if (readSize > 0 && buffer[readSize - 1] == '\n') {
            readSize -= 1;
        }

        /// set end of read
        buffer[readSize] = 0;

        Base::Msg(2, "CG: Read '%s' = '%s'\n", parameter.c_str(), buffer);

        success = 1;

        fail_close:
        if (success == 0) {
            Base::Msg(2, "Failed to read %s\n", path.c_str());
        }
        close(fd);
        fail:
        return success;
    }

    int writeStat(const string& parameter, const string& value, bool maybe=false) {
        int success = 0;
        ssize_t writeSize = 0;

        Base::Msg(2, "CG: Write %s = %s\n", parameter.c_str(), value.c_str());

        string path = getPath(parameter);

        /// check file descriptor
        int fd = open(path.c_str(), O_WRONLY | O_TRUNC);
        if (fd < 0) {
            if (maybe) {
                goto fail;
            } else {
                Base::Die("Cannot write %s: %m", path.c_str());
            }
        }

        /// write and sanity check
        writeSize = write(fd, value.c_str(), value.size());
        if (writeSize < 0) {
            if (maybe) {
                goto fail_close;
            } else {
                Base::Die("%s: %m", Base::StrCat("Cannot set ", path, " to ", value).c_str());
            }
        }

        if (writeSize != (ssize_t)value.size()) {
            Base::Die("Short write to %s (%zd out of %zu bytes) err:%m", path.c_str(), writeSize, value.size());
        }

        success = 1;
        fail_close:
        if (success == 0) {
            Base::Msg(2, "Failed to write %s=%s\n", path.c_str(), value.c_str());
        }
        close(fd);
        fail:

        return success;
    }

    bool populated() {
        readStat("cgroup.events");
        return strstr(buffer, "populated 1") != nullptr;
    }

    /// A run never shares its control group with what an earlier one left behind, as when its keeper was killed
    void killLeftovers() {
        writeStat("cgroup.kill", "1");
        for (int waitedMs = 0; populated(); waitedMs += 1) {
            if (waitedMs == kLeftoverWaitMs) {
                Base::Die("Processes left in control group %s outlived cgroup.kill", cgName.c_str());
            }
            usleep(1000);
        }
    }

  public:
    void init(int cgId) {
        cgName = Base::StrCat("box-", cgId);
        Base::Msg("Using control group %s\n", cgName.c_str());
    }

    /// creates cgroup and enables controllers
    void prepare() {
        Base::Msg("Preparing control group %s\n", cgName.c_str());
        
        // Create the cgroup directory
        struct stat st;
        string path = Base::StrCat(cgRootPath, '/', cgName);
        if (stat(path.c_str(), &st) >= 0 || errno != ENOENT) {
            Base::Msg("Control group %s already exists, trying to empty it.\n", path.c_str());
            killLeftovers();
            if (rmdir(path.c_str()) < 0) {
                Base::Die("Failed to reset control group %s: %m", path.c_str());
            }
        }

        if (mkdir(path.c_str(), 0777) < 0) {
            Base::Die("Failed to create control group %s: %m", path.c_str());
        }
        
        // Enable controllers in v2 - try to enable at root level first
        string controllers_path = Base::StrCat(cgRootPath, "/cgroup.subtree_control");
        int fd = open(controllers_path.c_str(), O_WRONLY);
        if (fd < 0) {
            Base::Die("Cannot open cgroup.subtree_control: %m");
        }
        
        vector<string> controllerNames = {"+memory", "+cpuset"};
        for (const auto& controllerName : controllerNames) {
            ssize_t written = write(fd, controllerName.c_str(), controllerName.length());
            if (written < 0) {
                close(fd);
                Base::Die("Failed to enable controller %s: %m", controllerName.c_str());
            } else {
                Base::Msg("Successfully enabled controller %s\n", controllerName.c_str());
            }
        }
        close(fd);

        /// Copy CPU and memory configuration from parent
        if (readStat("cpuset.cpus.effective", true)) {
            writeStat("cpuset.cpus", buffer, true);
        }

        if (readStat("cpuset.mems.effective", true)) {
            writeStat("cpuset.mems", buffer, true);
        }
    }

    void applyLimits() {
        if (cgMemoryLimitKB) {
            writeStat("memory.max", Base::StrCat(cgMemoryLimitKB << 10));
            writeStat("memory.swap.max", Base::StrCat(cgMemoryLimitKB << 10), true);
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

    /// removes cgroup
    void cleanup() {
        // Check if any processes are still in the cgroup
        if (readStat("cgroup.procs", true)) {
            if (buffer[0]) {
                Base::Die("Some processes left in cgroup %s, failed to remove it", cgName.c_str());
            }
        }

        string path = Base::StrCat(cgRootPath, '/', cgName);
        if (rmdir(path.c_str()) < 0) {
            Base::Die("Cannot remove control group %s: %m", path.c_str());
        }
    }

    unsigned long long cpuTimeNs() {
        // In v2, cpu.stat contains usage_usec
        if (readStat("cpu.stat", true)) {
            char* usage_line = strstr(buffer, "usage_usec ");
            if (usage_line) {
                unsigned long long usec = atoll(usage_line + strlen("usage_usec "));
                return usec * 1000; // Convert microseconds to nanoseconds
            }
        }
        return 0;
    }

    unsigned long long cpuTimeMs() {
        return cpuTimeNs() / (int)1e6;
    }

    RunStats::TimeStat getFullTime() {
        RunStats::TimeStat timeStat = {0, 0, 0, 0};

        if (readStat("cpu.stat", true)) {
            // v2 format: usage_usec 12345\nuser_usec 12345\nsystem_usec 67890\n...
            char* usage_line = strstr(buffer, "usage_usec ");
            char* user_line = strstr(buffer, "user_usec ");
            char* system_line = strstr(buffer, "system_usec ");

            if (usage_line) {
                timeStat.cpuTimeNs = atoll(usage_line + strlen("usage_usec ")) * 1000;
            }
            if (user_line) {
                timeStat.userTimeNs = atoll(user_line + strlen("user_usec ")) * 1000;
            }
            if (system_line) {
                timeStat.systemTimeNs = atoll(system_line + strlen("system_usec ")) * 1000;
            }
        }

        return timeStat;
    };

    size_t memoryKB() {
        // Memory usage statistics from v2
        size_t mem = 0;
        if (readStat("memory.peak", true)) {
            mem = atoll(buffer);
        } else {
            Base::Msg("Failed to read memory from cgroup");
        }

        // Try swap peak as well
        if (readStat("memory.swap.peak", true)) {
            size_t swap = atoll(buffer);
            if (swap > mem) {
                mem = swap;
            }
        }

        return mem >> 10; // Convert bytes to KB
    }
};