#pragma once

#include <string>
#include <vector>
#include <istream>

using std::string;
using std::vector;

struct ProcessConfig {
    enum Modes {
        kUnspecified,  // comment
        kInit,
        kRun,
        kCleanup
    };

    struct Environment {
        int useDefaultRules;   /// LIBC_FATAL_STDERR_=1
        int passEnvironment;   /// --full-env      inherit environment from system
        vector<string> rules;  /// --env=a=b       custom rules for environment

        Environment() {
            useDefaultRules = true;
            passEnvironment = false;
        }
    };

    struct DirRules {
         struct DirRule {
            std::string boxPath;         // A relative path to box/
            std::string localPath;       // This can be an absolute path or a relative path starting with "./"
            unsigned int flags;     // DIR_FLAG_xxx

            DirRule(std::string boxPath="", unsigned int flags = 8)
                : boxPath(boxPath), localPath(""), flags(flags) {
            }

            DirRule(std::string boxPath, std::string localPath, unsigned int flags = 8)
                : boxPath(boxPath), localPath(localPath), flags(flags) {
            }

            friend std::istream& operator>>(std::istream& stream, DirRule& rhs) {
                stream >> rhs.boxPath;
                return stream;
            }
        };
        vector<DirRule> rules;
    };

    struct DiskQuota {
        int blockQuota;  /// --quota-blocks limit on disk quota blocks alloc. 0 = unlimited.
        int inodeQuota;  /// --quota-inodes number of allocated inodes

        DiskQuota() {
            blockQuota = 0;
            inodeQuota = 0;
        }
    };

    struct FilePermissions {
        vector<string> rules;  /// custom rules for file permissions
        int fullPermissionsOverFolder;

        FilePermissions() {
            fullPermissionsOverFolder = true;
        }
    };

    /// basic configs
    int mode;       /// --init --run --cleanup
    int boxId;      /// --box-id=x      id of the sandbox and cgroup. Needs to be specified.
    int processId;  /// --processId=x   specify if 2 tasks are run in the same box but with access to different limits.
                    /// Default=0;

    /// logger config
    int verboseLevel;  /// --verbose       set verbosity value
    string metaFile;   /// --meta=file.txt specify the path for the meta file (the stats). relative to the run location

    /// time limits
    unsigned long long cpuTimeLimitMs;   /// --time=x       CPU (user + system) time limit to x seconds
    unsigned long long wallTimeLimitMs;  /// --wall-time=x  Wall time limit to x seconds
    unsigned long long extraTimeMs;      /// --extra-time=x kill after any of the times reach setValue + extraTime
    unsigned long long checkIntervalMs;  ///                time in ms between 2 checks of the sandbox process status

    /// memory limits
    int memoryLimitKB;  /// --memory=x          memory limit to x KB. Default = unlimited
    int stackLimitKB;   /// --stack=x           stack limit to x KB. Default = unlimited

    /// files
    string redirectStdin;   /// --stdin=file.txt    redirect stdin to this
    string redirectStdout;  /// --stdout=file.txt   redirect stdout to this
    string redirectStderr;  /// --stderr=file.txt   redirect stderr to this
    string execDirectory;   /// --chdir=dif         process will be run from dis dir
    int fileSizeLimitKB;    /// --file-size=x       limit file size to x KB. Default = unlimited

    /// misc
    int maxProcesses;  /// --processes{=x}  max number of processes that can be created from process. default = 1,
                       /// unspecified value = unlimited
    int shareNetwork;  /// --share-net      if specified, the process will share network access from parent

    bool swapPipeOpenOrder;  /// --interactive  open stdout first, then stdin. Avoid fifo blocking open.
    bool legacyMetaJson;     /// --legacy-json  prints meta file in old format (version 2.0)

    string runCommand;  /// last argumet of command line. The command which will be run in box

    /// rules for stuff
    Environment environment;
    DirRules dirRules;
    DiskQuota diskQuota;
    FilePermissions filePermissions;

    ProcessConfig() : environment(), dirRules(), diskQuota(), filePermissions() {
        this->mode = kUnspecified;
        this->boxId = -1;
        this->processId = 0;

        this->verboseLevel = 0;
        this->metaFile = "";

        this->cpuTimeLimitMs = 0;
        this->wallTimeLimitMs = 0;
        this->extraTimeMs = 0;
        this->checkIntervalMs = 100;

        this->memoryLimitKB = 0;
        this->stackLimitKB = 0;

        this->redirectStdin = "";
        this->redirectStdout = "";
        this->redirectStderr = "";
        this->execDirectory = "";
        this->fileSizeLimitKB = 0;

        this->maxProcesses = 1;
        this->shareNetwork = 0;
        this->swapPipeOpenOrder = 0;

        this->runCommand = "";
    }
};

