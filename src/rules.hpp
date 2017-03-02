
#include <limits.h>
#include <mntent.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/quota.h>
#include <unistd.h>

#include <map>
#include <string>
#include <vector>

#include "cpp-base/string_utils.hpp"
#include "cpp-base/logger.hpp"
#include "cpp-base/os.hpp"

#include "config.hpp"


using Base::Die;
using Base::Msg;

/// Environment, DirRules, DiskQuotas, FilePermisions
class Rules {
  public:
    /*** Environment rules ***/
    /// set environment rules for the isolated program
    class Environment {
      public:
        Environment(const ProcessConfig::Environment& config)
                : allRules({}) {
            this->passEnvironment = config.passEnvironment;

            for (int itr = 0; environ[itr]; itr += 1) {
                auto rule = getRule(environ[itr]);
                allRules[rule.first] = rule.second;
            }

            addDefaultRules();

            for (const auto& rule : config.rules) {
                addRule(rule);
            }
        }

        std::pair<std::string, std::string> getRule(const std::string& commandLineRule) {
            // search for "="
            std::size_t equalPosition = commandLineRule.find("=");

            if (equalPosition == std::string::npos) {
                // equal not found, inherit from global environment.
                return {commandLineRule, allRules[commandLineRule]};
            } else {
                return {commandLineRule.substr(0, equalPosition),
                                 commandLineRule.substr(equalPosition + 1)};
            }
        };

        int passEnvironment;

        std::map<std::string, std::string> allRules;

        void addDefaultRules() {
            addRule("LIBC_FATAL_STDERR_=1");    /// send fatal errors to stderr
        }

        // return true if the rule is correct and it was added/a old rule was updated
        int addRule(const std::string& commandLineRule) {
            std::pair<std::string, std::string> rule = getRule(commandLineRule);
            if (rule.first == "") {
                return 0;
            }

            allRules[rule.first] = rule.second;
            return 1;
        }

        // returns the environment variables in char** format
        // including the new rules as well as the ones inherited from environ
        char** getEnvironment() {
            int numRules = 0;
            for (auto rule : allRules) {
                // don't count empty rules for the final number of rules
                numRules += !rule.second.empty();
            }

            char** env = (char**) malloc((numRules + 1) * sizeof(char*));
            int currentRule = 0;

            env[numRules] = NULL;
            for (auto rule : allRules) {
                if (rule.second.empty()) {
                    // no empty rules
                    continue;
                }

                env[currentRule++] = strdup(Base::StrCat(rule.first, "=", rule.second).c_str());
            }

            return env;
        }
    };

    /*** Directory rules ***/
    /// mount system tools (such as bin, dev, lib, proc) into the sandbox
    class DirRules {
      public:
        enum DirRuleFlag {
            FLAG_RW = (1 << 0),         // Allow read-write access.
            FLAG_NOEXEC = (1 << 1),     // Disallow execution of binaries.
            FLAG_FS = (1 << 2),         // For 'proc' or 'sysfs'
                                        // Instead of binding a directory, mount a device-less filesystem called 'in'.
            FLAG_MAYBE = (1 << 3),      // Silently ignore the rule if the directory to be bound does not exist.
            FLAG_DEV = (1 << 4),        // Allow access to character and block devices.
        };

      private:
        struct DirRule {
            std::string boxPath;         // A relative path to box/
            std::string localPath;       // This can be an absolute path or a relative path starting with "./"
            unsigned int flags;     // DIR_FLAG_xxx
        };

      public:
        DirRules(const ProcessConfig::DirRules& UNUSED config) {
            /// add default rules before any other rule can be added.
            /// in this way the default rules can be overwitten
            addDefaultRules();
        }

        int add(std::string boxPath, std::string localPath, unsigned int flags) {
            // Make sure that "boxPath" is relative
            while (boxPath.size() && boxPath[0] == '/') {
                boxPath = boxPath.substr(1);
            }

            // Check boxPath
            if (boxPath.size() == 0 || localPath.size() == 0) {
                return 0;
            }

            // Check "localPath"
            if (flags & FLAG_FS) {
                if (localPath[0] == '/') {
                    return 0;
                }
            } else if (localPath[0] != '/' && localPath.substr(0, 2) != "./") {
                return 0;
            }

            // Override an existing rule
            for (DirRule& rule : allDirRules) {
                if (rule.boxPath == boxPath) {
                    rule.localPath = localPath;
                    rule.flags = flags;
                    return 1;
                }
            }

            // Add a new rule
            allDirRules.push_back({boxPath, localPath, flags});

            return 1;
        }

        int add(std::string boxPath, unsigned int flags=0) {
            return add(boxPath, "/" + boxPath, flags);
        }

        void addDefaultRules() {
            add("box", "./box", FLAG_RW);
            add("bin");
            add("dev", FLAG_DEV); /// TODO Is this really necesary?
            add("lib");
            add("lib64", FLAG_MAYBE);
            add("proc", "proc", FLAG_FS);
            add("usr");
        }

        void applyRules() {
            for (DirRule rule : allDirRules) {
                if (rule.localPath.size() == 0) {
                    Msg("Not binding anything on %s\n", rule.boxPath.c_str());
                    continue;
                }

                if ((rule.flags & FLAG_MAYBE) && !Base::DirExists(rule.localPath.c_str())) {
                    Msg("Not binding %s on %s (does not exist)\n", rule.localPath.c_str(), rule.boxPath.c_str());
                    continue;
                }

                char rootInBox[1024];
                snprintf(rootInBox, sizeof(rootInBox), "root/%s", rule.boxPath.c_str());
                Base::MakeDir(rootInBox);

                // convert rules from DIR_FLAGS_XXX to mount rule
                unsigned long mount_flags = 0;

                if (!(rule.flags & FLAG_RW)) {
                    mount_flags |= MS_RDONLY;
                }

                if (rule.flags & FLAG_NOEXEC) {
                    mount_flags |= MS_NOEXEC;
                }

                if (!(rule.flags & FLAG_DEV)) {
                    mount_flags |= MS_NODEV;
                }

                if (rule.flags & FLAG_FS) {
                    Msg("Mounting %s on %s (flags %lx)\n", rule.localPath.c_str(), rule.boxPath.c_str(), mount_flags);
                    if (mount("none", rootInBox, rule.localPath.c_str(), mount_flags, "") < 0) {
                        Die("Cannot mount %s on %s: %m", rule.localPath.c_str(), rule.boxPath.c_str());
                    }
                } else {
                    mount_flags |= MS_BIND | MS_NOSUID;
                    Msg("Binding %s on %s (flags %lx)\n", rule.localPath.c_str(), rule.boxPath.c_str(), mount_flags);
                    // Most mount flags need remount to work
                    if (mount(rule.localPath.c_str(), rootInBox, "none", mount_flags, "") < 0 ||
                        mount(rule.localPath.c_str(), rootInBox, "none", MS_REMOUNT | mount_flags, "") < 0) {
                        Die("Cannot mount %s on %s: %m", rule.localPath.c_str(), rule.boxPath.c_str());
                    }
                }
            }
        }

        std::vector<DirRule> allDirRules;
    };

    /*** Disk quotas ***/
    /// not fully implemented.
    /// limit disk space overall used in the sandbox
    class DiskQuota {
        static char* findDevice(const char* path) {
            FILE* f = setmntent("/proc/mounts", "r");
            if (!f)
                Die("Cannot open /proc/mounts: %m");

            struct mntent* me;
            int best_len = 0;
            char* best_dev = NULL;
            while ((me = getmntent(f))) {
                if (!Base::PathBeginsWith(me->mnt_fsname, "/dev"))
                    continue;

                if (Base::PathBeginsWith(path, me->mnt_dir)) {
                    int len = strlen(me->mnt_dir);
                    if (len > best_len) {
                        best_len = len;
                        free(best_dev);
                        best_dev = strdup(me->mnt_fsname);
                    }
                }
            }
            endmntent(f);
            return best_dev;
        }

      public:
        int processUid;     /// inherited from Process
        int blockQuota;     /// limit on disk quota blocks alloc
        int inodeQuota;     /// number of allocated inodes

        void applyQuota() {
            if (!blockQuota)
                return; // no disk quota set

            char cwd[PATH_MAX];
            if (!getcwd(cwd, sizeof(cwd)))
                Die("getcwd: %m");

            char* dev = findDevice(cwd);
            if (!dev)
                Die("Cannot identify filesystem which contains %s", cwd);
            Msg("Quota: std::mapped path %s to a filesystem on %s\n", cwd, dev);

            // Sanity check
            struct stat devStat, cwdStat;
            if (stat(dev, &devStat) < 0)
                Die("Cannot identify block device %s: %m", dev);
            if (!S_ISBLK(devStat.st_mode))
                Die("Expected that %s is a block device", dev);
            if (stat(".", &cwdStat) < 0)
                Die("Cannot stat cwd: %m");
            if (cwdStat.st_dev != devStat.st_rdev)
                Die("Identified %s as a filesystem on %s, but it is obviously false", cwd, dev);

            // Set disk quotas
            struct dqblk dq;
            bzero(&dq, sizeof(dq));
            dq.dqb_bhardlimit = blockQuota;    /* absolute limit on disk quota blocks alloc */
            dq.dqb_bsoftlimit = blockQuota;    /* preferred limit on disk quota blocks */
            dq.dqb_ihardlimit = inodeQuota;    /* maximum number of allocated inodes */
            dq.dqb_isoftlimit = inodeQuota;    /* preferred inode limit */
            dq.dqb_valid = QIF_LIMITS;          /* limit blocks and inodes */

            // Apply disk quotas
            if (quotactl(QCMD(Q_SETQUOTA, USRQUOTA), dev, processUid, (caddr_t)&dq) < 0)
                Die("Cannot set disk quota: %m");

            Msg("Quota: Set block quota %d and inode quota %d\n", blockQuota, inodeQuota);
            free(dev);
        }

        DiskQuota(const ProcessConfig::DiskQuota& config, int processUid) {
            this->processUid = processUid;
            this->blockQuota = config.blockQuota;
            this->inodeQuota = config.inodeQuota;
        }
    };

    /*** whitelists all files that can be accesed / used in box ***/
    /// set specifie file permissions inside the sandbox.
    /// the default usage is to whitelist everything in the box folder
    /// and blacklist files.
    /// * usefull when more isolated processes need to comunicate but they want
    /// * to keep stuff from each other
    class FilePermissions {
        struct Permission {
            std::string path;
            std::string mode;    /// std::string with xwr, each of them only once
        };

        std::vector<Permission> allPermissions;
        bool fullPermissionsOverFolder;

        std::string modeFromString(const std::string& mode) {
            int bitmask = 0;

            for (char c : mode) {
                if (c == 'x' or c == 'X') {
                    bitmask |= (1 << 0);
                }
                if (c == 'w' or c == 'W') {
                    bitmask |= (1 << 1);
                }
                if (c == 'r' or c == 'R') {
                    bitmask |= (1 << 2);
                }
            }

            std::string result = "";
            std::string modes = "xwr";
            for (int i = 0; i < 3; i += 1) {
                if (bitmask & (1 << i)) {
                    result += modes[i];
                }
            }

            return result;
        }

      public:
        void addRule(std::string path, std::string mode) {
            Permission p;
            p.path = path;
            p.mode = modeFromString(mode);
            allPermissions.push_back(p);
        }

        void addRule(std::string rule) {
            auto colonLocation = rule.find(":");
            if (colonLocation == std::string::npos) {
                addRule(rule, "");
            } else {
                addRule(rule.substr(0, colonLocation), rule.substr(colonLocation + 1, rule.size()));
            }
        }

        void applyRules(uid_t uid) {
            char* pwd = get_current_dir_name();
            if (strcmp(pwd, "/box") != 0) {
                Die("FilePermissions::applyRules must be run in /box | %s\n", pwd);
            }

            if (geteuid()) {
                Die("FilePermissions::applyRules must be run as root\n");
            }

            /// delete all privileges for other
            Base::Chmod("750 .");
            Base::Chmod("750 *");

            std::string command = "";
            for (const Permission& rule : allPermissions) {
                if (rule.mode == "") {
                    command += Base::StrCat("-x u:", uid, " ", rule.path, " ");
                } else {
                    command += Base::StrCat("-m u:", uid, ":", rule.mode, " ", rule.path, " ");
                }
            }

            Msg("permissions command:\t%s\n", command.c_str());
            Base::Setfacl(command);
        }

        FilePermissions(const ProcessConfig::FilePermissions& config) {
            this->fullPermissionsOverFolder = config.fullPermissionsOverFolder;

            if (fullPermissionsOverFolder) {
                addRule(".", "rxw");
                addRule("*", "rxw");
            }

            for (auto rule : config.rules) {
                addRule(rule);
            }
        }
    };
};

