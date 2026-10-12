#pragma once

#include <stddef.h>
#include <string>

/// What a run ended as, written to the meta file
class RunStats {
  public:
    /// Anything except OK is a fail; the evaluator maps the numbers, so they never move
    enum ResultCode {
        UNDEFINED = 0,
        OK,
        RESTRICTED_FUNCTION,
        TIME_LIMIT_EXCEEDED,
        WALL_TIME_LIMIT_EXCEEDED,
        MEMORY_LIMIT_EXCEEDED,
        OUTPUT_LIMIT_EXCEEDED,
        NON_ZERO_EXIT_STATUS,
        RUNTIME_ERROR,
        ABNORMAL_TERMINATION,
        INTERNAL_ERROR,
    };

    /// Nanoseconds, at the resolution the platform has: a Linux cgroup accounts in microseconds
    struct TimeStat {
        unsigned long long wallTimeNs = 0;    /// wall clock time from the exec
        unsigned long long cpuTimeNs = 0;     /// CPU time, user and kernel
        unsigned long long userTimeNs = 0;    /// CPU time in user mode
        unsigned long long systemTimeNs = 0;  /// CPU time in kernel mode
    };

    TimeStat timeStat;
    size_t memoryKB = 0;  /// peak memory of the control group

    int terminalSignal = 0;  /// signal that killed the program
    int exitCode = 0;        /// exit code the program ended with on its own
    bool processWasKilled = false;  /// killed by the keeper for a limit
    ResultCode resultCode = INTERNAL_ERROR;
    std::string internalMessage;

    static const std::string version;
};

const std::string RunStats::version = "2.4";
