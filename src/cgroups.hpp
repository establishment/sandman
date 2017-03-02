#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include <string>

#include "runstats.hpp"

#include "cpp-base/string_utils.hpp"
#include "cpp-base/os.hpp"
#include "cpp-base/logger.hpp"

/// CGroups API
class CGroups {
  public:
    /// A subsystem ⁠ represents a single resource, such as CPU time or memory
    struct CGSubsystem {
        std::string name;
        bool optional;
    };

    static CGSubsystem cgMemory;
    static CGSubsystem cgCpuacct;
    static CGSubsystem cgCpuset;
    static CGSubsystem cgAllSubSystems[3];
    static std::string cgRootPath;   /// "/sys/fs/cgroup":

    CGroups() {
        this->cgName = "";
        this->cgMemoryLimitKB = 0;
        this->useCGTiming = 1;
    }

    std::string cgName;              /// name of the control goup
    int cgMemoryLimitKB;        /// memory limit for that cg
    int useCGTiming;            /// query process time from control group - default = true

    static const int kCGBufferSize = 4096;
    char buffer[kCGBufferSize];

  protected:
    /// a parameter is a child of a subsystem, like memory.usage_in_bytes or cpuacct.usage under cpuacct
    std::string getPath(CGSubsystem subsystem, const std::string& parameter) {
        return Base::StrCat(cgRootPath, '/', subsystem.name, '/', cgName, '/', parameter);
    }

    int readStat(CGSubsystem subsystem, const std::string& parameter, bool maybe=false) {
        int success = 0;
        int readSize = 0;

        std::string path = getPath(subsystem, parameter);

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

    int writeStat(CGSubsystem subsystem, const std::string& parameter, const std::string& value, bool maybe=false) {
        int success = 0;
        ssize_t writeSize = 0;

        Base::Msg(2, "CG: Write %s = %s\n", parameter.c_str(), value.c_str());

        std::string path = getPath(subsystem, parameter);

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
                Base::Die("Cannot set %s to %s: %m", path.c_str(), value.c_str());
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

  public:
    static void SanityCheck() {
        /// sanity check the presence of cgroups in the system
        if (!Base::DirExists(cgRootPath.c_str())) {
            Base::Die("Control group filesystem at %s not mounted", cgRootPath.c_str());
        }
    }

    void init(int cgId) {
        cgName = Base::StrCat("box-", cgId);
        Base::Msg("Using control group %s\n", cgName.c_str());
    }

    /// creates cgroup
    /// sets cpu accesibility (cores) and memory accesibility (RAM nodes) if any from parent process
    void prepare() {
        Base::Msg("Preparing control group %s\n", cgName.c_str());
        for (auto subsystem : cgAllSubSystems) {
            struct stat st;
            std::string path = getPath(subsystem, "");
            if (stat(path.c_str(), &st) >= 0 || errno != ENOENT) {
                Base::Msg("Control group %s already exists, trying to empty it.\n", path.c_str());
                if (rmdir(path.c_str()) < 0) {
                    Base::Die("Failed to reset control group %s: %m", path.c_str());
                }
            }

            if (mkdir(path.c_str(), 0777) < 0 && !subsystem.optional) {
                Base::Die("Failed to create control group %s: %m", path.c_str());
            }
        }

        /// If cpuset module is enabled, copy allowed cpus and memory nodes from parent group
        /// limits the cpus which can be used by target process
        /// usefull in a multi cored environment
        if (readStat(cgCpuset, "cpuset.cpus", true)) { /// try to read
            writeStat(cgCpuset, "cpuset.cpus", buffer); /// write what was just read
        }

        /// sets RAM nodes which this program can use
        /// can be specified to be the first 2 GB of ram for example
        if (readStat(cgCpuset, "cpuset.mems", true)) { /// try to read
            writeStat(cgCpuset, "cpuset.mems", buffer); /// write what was just read
        }
    }

    void enter() {
        Base::Msg("Entering control group %s\n", cgName.c_str());

        for (auto subsystem : cgAllSubSystems) {
            /// add current pid to be contored by the cgroup for all target subsystems
            writeStat(subsystem, "tasks", Base::StrCat(getpid()), subsystem.optional);
        }

        if (cgMemoryLimitKB) {
            /// limit RAM used by cgroup
            writeStat(cgMemory, "memory.limit_in_bytes", Base::StrCat(cgMemoryLimitKB << 10));

            /// limit swap space used by cgroup if it can
            writeStat(cgMemory, "memory.memsw.limit_in_bytes", Base::StrCat(cgMemoryLimitKB << 10), true);
        }

        /// time is queried from cgroup for the process. Reset the stats for that cgroup
        if (useCGTiming) {
            /// reset the value of cgroup consumed time
            writeStat(cgCpuacct, "cpuacct.usage", "0");
        }
    }

    /// removes cgroup
    void cleanup() {
        /// search for each subsystem (memory, cpuset, acuacct) and delete them
        for (auto subsystem : cgAllSubSystems) {
            if (subsystem.optional) {
                if (!readStat(subsystem, "tasks", true)) {
                    continue;
                }
            } else {
                readStat(subsystem, "tasks");
            }

            if (buffer[0]) {
                Base::Die("Some tasks left in subsystem %s of cgroup %s, failed to remove it",
                    subsystem.name.c_str(), cgName.c_str());
            }

            std::string path = getPath(subsystem, "");

            if (rmdir(path.c_str()) < 0) {
                Base::Die("Cannot remove control group %s: %m", path.c_str());
            }
        }
    }

    unsigned long long cpuTimeNs() {
        readStat(cgCpuacct, "cpuacct.usage");
        unsigned long long ns = atoll(buffer);
        return ns;
    }

    unsigned long long cpuTimeMs() {
        return cpuTimeNs() / (int)1e6;
    }

    RunStats::TimeStat getFullTime() {
        RunStats::TimeStat timeStat;
        timeStat.wallTimeMs = 0;
        timeStat.cpuTimeMs = cpuTimeMs();

        /// http://stackoverflow.com/questions/3875801/convert-jiffies-to-seconds/6786757#6786757
        /// returns in jiffies. jiffies/sec = 100. num_juffies / 100 * 1000 to ms
        readStat(cgCpuacct, "cpuacct.stat");
        timeStat.userTimeMs = 10 * atoll(strstr(buffer, "user ") + strlen("user "));
        timeStat.systemTimeMs = 10 * atoll(strstr(buffer, "system ") + strlen("system "));

        return timeStat;
    };

    size_t memoryKB() {
        // Memory usage statistics
        size_t mem = 0, memsw = 0;
        if (readStat(cgMemory, "memory.max_usage_in_bytes", true)) {
            mem = atoll(buffer);
        } else {
            Base::Msg("Failed to read memory from cgroup");
        }

        if (readStat(cgMemory, "memory.memsw.max_usage_in_bytes", true)) {
            memsw = atoll(buffer);
            if (memsw > mem) {
                mem = memsw;
            }
        } else {
            Base::Msg("Failed to read swap memory from cgroup");
        }

        return mem >> 10;
    }
};

CGroups::CGSubsystem CGroups::cgMemory = {"memory", false};
CGroups::CGSubsystem CGroups::cgCpuacct = {"cpuacct", false};
CGroups::CGSubsystem CGroups::cgCpuset = {"cpuset", true};

CGroups::CGSubsystem CGroups::cgAllSubSystems[] = {cgMemory, cgCpuacct, cgCpuset};

std::string CGroups::cgRootPath = "/sys/fs/cgroup";
