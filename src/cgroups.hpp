#include "runstats.hpp"
#include "cpp-base/time.hpp"

/// CGroups API
class CGroups {
  public:
    PreciseTimer pt;
    int cgMemoryLimitKB;    

    static void SanityCheck() {
    }

    void init(int cgId) {
    }

    /// creates cgroup
    /// sets cpu accesibility (cores) and memory accesibility (RAM nodes) if any from parent process
    void prepare() {
    }

    void enter() {
        pt.start();
    }

    /// removes cgroup
    void cleanup() {
    }

    unsigned long long cpuTimeNs() {
        return pt.secElapsed() * 1e9;
    }

    unsigned long long cpuTimeMs() {
        return pt.msElapsed();
    }

    RunStats::TimeStat getFullTime() {
        RunStats::TimeStat timeStat;
        timeStat.wallTimeMs = 0;
        timeStat.cpuTimeMs = pt.msElapsed();
        timeStat.userTimeMs = pt.msElapsed();
        timeStat.systemTimeMs = pt.msElapsed();
        return timeStat;
    };

    size_t memoryKB() {
        return 0;
    }
};

