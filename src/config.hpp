#pragma once

#include <string>
#include <vector>

using std::string;
using std::vector;

/// Everything the command line says about one isolate invocation
struct ProcessConfig {
    enum Modes { kUnspecified, kInit, kRun, kCleanup };

    Modes mode = kUnspecified;  /// --init --run --cleanup
    int boxId = 0;              /// --box-id=x      id of the sandbox, which the cgroup and the uids derive from
    int processId = 0;          /// --process-id=x  which of the box's jails this is, each with its own uid and cgroup

    int verboseLevel = 0;  /// --verbose
    string metaFile;       /// --meta=file.txt  where the run stats go, relative to the run location

    unsigned long long cpuTimeLimitMs = 0;   /// --time=x       CPU (user + system) time limit, given in seconds
    unsigned long long wallTimeLimitMs = 0;  /// --wall-time=x  wall time limit, given in seconds

    int memoryLimitKB = 0;  /// --memory=x  0 is unlimited
    int stackLimitKB = 0;   /// --stack=x   0 is unlimited

    string redirectStdin;        /// --stdin=file.txt
    string redirectStdout;       /// --stdout=file.txt
    string redirectStderr;       /// --stderr=file.txt
    string execDirectory;        /// --chdir=dir  the program's working directory, under the box
    int fileSizeLimitKB = 0;     /// --file-size=x  0 is unlimited
    int maxProcesses = 16;       /// --processes=x  cap on the processes and threads, 0 is unlimited
    bool swapPipeOpenOrder = false;  /// --interactive  open stdout before stdin, so two jails on fifos don't deadlock

    vector<string> runCommand;  /// the positional arguments, the program and its arguments

    vector<string> environmentRules;  /// --env=VAR=value, or --env=VAR to inherit isolate's own
    vector<string> includeDirs;       /// --include-dir=path  host directories bound read-only into the jail
    vector<string> permissionRules;   /// --permission=path:rwx  what the program's uid may do with box files
    int quotaBlocksKB = 0;            /// --quota-blocks  what each of the box's uids may own on its filesystem
    int quotaInodes = 0;              /// --quota-inodes
};
