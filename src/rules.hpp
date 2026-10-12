#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/quota.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include "cpp-base/os.hpp"
#include "cpp-base/string_utils.hpp"

#include "config.hpp"
#include "die.hpp"

using Base::Die;
using Base::Msg;

/// Environment, DirRules, DiskQuota, FilePermissions
class Rules {
  public:
    /// The program's environment is only what the rules name: nothing of isolate's own leaks into the box
    class Environment {
        std::map<std::string, std::string> variables;

        /// A rule without a value inherits the variable from isolate's own environment, if set there
        void add(const std::string& rule) {
            size_t equal = rule.find('=');
            std::string name = rule.substr(0, equal);
            if (name.empty()) {
                Die("--env rule without a variable name: %s", rule.c_str());
            }
            if (equal == std::string::npos) {
                const char* inherited = getenv(name.c_str());
                variables[name] = inherited ? inherited : "";
            } else {
                variables[name] = rule.substr(equal + 1);
            }
        }

      public:
        Environment(const vector<string>& rules) {
            add("LIBC_FATAL_STDERR_=1");  /// fatal errors go to stderr, where the program's output expects them
            for (const std::string& rule : rules) {
                add(rule);
            }
        }

        /// A variable with an empty value is left out altogether
        char** getEnvironment() {
            std::vector<std::string> entries;
            for (const auto& [name, value] : variables) {
                if (!value.empty()) {
                    entries.push_back(name + "=" + value);
                }
            }
            return Base::StringToCharSS(entries);
        }
    };

    /// What of the host the jail sees: the box read-write, the system's binaries and libraries read-only
    class DirRules {
        enum Flags {
            FLAG_RW = 1 << 0,     /// read-write, otherwise read-only
            FLAG_FS = 1 << 1,     /// a filesystem of that type rather than a bind, as for proc
            FLAG_MAYBE = 1 << 2,  /// skipped when the host has no such directory
        };

        struct DirRule {
            std::string boxPath;    /// relative to the jail's root
            std::string localPath;  /// absolute on the host, or relative to the box's directory
            unsigned flags;
        };

        std::vector<DirRule> rules = {
            {"box", "./box", FLAG_RW}, {"bin", "/bin", 0},        {"lib", "/lib", 0},
            {"lib64", "/lib64", FLAG_MAYBE}, {"proc", "proc", FLAG_FS}, {"usr", "/usr", 0},
        };

      public:
        DirRules(const vector<string>& includeDirs) {
            for (std::string boxPath : includeDirs) {
                while (!boxPath.empty() && boxPath[0] == '/') {
                    boxPath = boxPath.substr(1);
                }
                if (boxPath.empty()) {
                    Die("--include-dir needs a path");
                }
                rules.push_back({boxPath, "/" + boxPath, FLAG_MAYBE});
            }
        }

        void applyRules() {
            for (const DirRule& rule : rules) {
                if ((rule.flags & FLAG_MAYBE) && !Base::DirExists(rule.localPath)) {
                    Msg("Not binding %s on %s (does not exist)\n", rule.localPath.c_str(), rule.boxPath.c_str());
                    continue;
                }

                std::string rootInBox = "root/" + rule.boxPath;
                Base::MakeDir(rootInBox);

                /// Nothing a program finds in the jail is a device
                unsigned long mountFlags = MS_NODEV;
                if (!(rule.flags & FLAG_RW)) {
                    mountFlags |= MS_RDONLY;
                }

                if (rule.flags & FLAG_FS) {
                    Msg("Mounting %s on %s (flags %lx)\n", rule.localPath.c_str(), rule.boxPath.c_str(), mountFlags);
                    if (mount("none", rootInBox.c_str(), rule.localPath.c_str(), mountFlags, "") < 0) {
                        Die("%s: %m", Base::StrCat("Cannot mount ", rule.localPath, " on ", rule.boxPath).c_str());
                    }
                } else {
                    mountFlags |= MS_BIND | MS_NOSUID;
                    Msg("Binding %s on %s (flags %lx)\n", rule.localPath.c_str(), rule.boxPath.c_str(), mountFlags);
                    /// A bind takes its flags only on a remount
                    if (mount(rule.localPath.c_str(), rootInBox.c_str(), "none", mountFlags, "") < 0 ||
                        mount(rule.localPath.c_str(), rootInBox.c_str(), "none", MS_REMOUNT | mountFlags, "") < 0) {
                        Die("%s: %m", Base::StrCat("Cannot mount ", rule.localPath, " on ", rule.boxPath).c_str());
                    }
                }
            }
        }
    };

    /// What the box's users may own on the box's filesystem, which has to be mounted with usrquota
    class DiskQuota {
      public:
        static void apply(int blocksKB, int inodes, int firstUid, int uidCount) {
            if (!blocksKB && !inodes) {
                return;
            }
            int box = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (box < 0) {
                Die("open box dir: %m");
            }
            for (int uid = firstUid; uid < firstUid + uidCount; uid += 1) {
                struct dqblk quota;
                memset(&quota, 0, sizeof(quota));
                quota.dqb_bhardlimit = blocksKB;  /// in KB
                quota.dqb_bsoftlimit = blocksKB;
                quota.dqb_ihardlimit = inodes;
                quota.dqb_isoftlimit = inodes;
                quota.dqb_valid = QIF_LIMITS;
                if (syscall(SYS_quotactl_fd, box, QCMD(Q_SETQUOTA, USRQUOTA), uid, &quota) < 0) {
                    Die("quotactl_fd (the box's filesystem must be mounted with usrquota): %m");
                }
            }
            close(box);
            Msg("Quota: %d KB and %d inodes per user\n", blocksKB, inodes);
        }
    };

    /// What the program's uid may do with the box's files, as a named entry in each one's ACL; by default, anything at the top level
    class FilePermissions {
        struct Rule {
            std::string pattern;  /// a path under the box, or a glob of them
            int perm;             /// ACL_READ | ACL_WRITE | ACL_EXECUTE, or 0 to remove the uid's entry
        };

        std::vector<Rule> rules = {{".", ACL_READ | ACL_WRITE | ACL_EXECUTE}, {"*", ACL_READ | ACL_WRITE | ACL_EXECUTE}};

        static int permFromString(const std::string& mode) {
            int perm = 0;
            for (char c : mode) {
                if (c == 'r' || c == 'R') {
                    perm |= ACL_READ;
                } else if (c == 'w' || c == 'W') {
                    perm |= ACL_WRITE;
                } else if (c == 'x' || c == 'X') {
                    perm |= ACL_EXECUTE;
                } else {
                    Die("Unknown permission '%c', expected r, w or x", c);
                }
            }
            return perm;
        }

        static bool hasWildcards(const std::string& pattern) {
            return pattern.find_first_of("*?[") != std::string::npos;
        }

        /// A path expanded as the shell would, minus symlinks: root must not follow one the program left in the box
        static std::vector<std::string> expandPath(const std::string& pattern) {
            glob_t matches;
            int result = glob(pattern.c_str(), GLOB_NOMAGIC, nullptr, &matches);
            if (result == GLOB_NOMATCH) {
                return {};
            }
            if (result != 0) {
                Die("glob %s failed", pattern.c_str());
            }

            std::vector<std::string> paths;
            for (size_t i = 0; i < matches.gl_pathc; i += 1) {
                if (!traversesSymlink(matches.gl_pathv[i])) {
                    paths.push_back(matches.gl_pathv[i]);
                }
            }
            globfree(&matches);
            return paths;
        }

        static bool traversesSymlink(const std::string& path) {
            for (size_t end = path.find('/', 1);; end = path.find('/', end + 1)) {
                struct stat st;
                if (lstat(path.substr(0, end).c_str(), &st) == 0 && S_ISLNK(st.st_mode)) {
                    return true;
                }
                if (end == std::string::npos) {
                    return false;
                }
            }
        }

        /// A file's ACL as the kernel stores it, or the one its mode bits amount to when it has none
        static std::vector<posix_acl_xattr_entry> readAcl(const std::string& path, mode_t mode) {
            char buffer[4096];
            ssize_t size = lgetxattr(path.c_str(), "system.posix_acl_access", buffer, sizeof(buffer));
            if (size < 0 && errno == ENODATA) {
                return {{ACL_USER_OBJ, (__le16)((mode >> 6) & 7), (__le32)ACL_UNDEFINED_ID},
                        {ACL_GROUP_OBJ, (__le16)((mode >> 3) & 7), (__le32)ACL_UNDEFINED_ID},
                        {ACL_OTHER, (__le16)(mode & 7), (__le32)ACL_UNDEFINED_ID}};
            }
            if (size < 0) {
                Die("getxattr %s: %m", path.c_str());
            }
            posix_acl_xattr_header* header = (posix_acl_xattr_header*)buffer;
            size_t entries = (size - sizeof(*header)) / sizeof(posix_acl_xattr_entry);
            if (size < (ssize_t)sizeof(*header) || header->a_version != POSIX_ACL_XATTR_VERSION ||
                sizeof(*header) + entries * sizeof(posix_acl_xattr_entry) != (size_t)size) {
                Die("Unexpected ACL on %s", path.c_str());
            }
            posix_acl_xattr_entry* first = (posix_acl_xattr_entry*)(header + 1);
            return std::vector<posix_acl_xattr_entry>(first, first + entries);
        }

        /// The uid's entry becomes perm (none removes it), the mask follows, and the top level shuts out everyone else
        static void setAcl(const std::string& path, uid_t uid, int perm, bool clearOther, bool mayVanish) {
            struct stat st;
            if (lstat(path.c_str(), &st) < 0) {
                /// The other jail of an interactive run may delete a file meanwhile
                if (errno == ENOENT && mayVanish) {
                    return;
                }
                Die("lstat %s: %m", path.c_str());
            }
            if (S_ISLNK(st.st_mode)) {
                Die("%s is a symlink", path.c_str());
            }

            std::vector<posix_acl_xattr_entry> acl;
            for (posix_acl_xattr_entry entry : readAcl(path, st.st_mode)) {
                if (entry.e_tag == ACL_MASK || (entry.e_tag == ACL_USER && entry.e_id == uid)) {
                    continue;
                }
                if (entry.e_tag == ACL_OTHER && clearOther) {
                    entry.e_perm = 0;
                }
                acl.push_back(entry);
            }
            if (perm) {
                acl.push_back({ACL_USER, (__le16)perm, (__le32)uid});
            }
            /// The mask caps every named entry and the owning group, so it is their union; without named entries there is none
            int mask = 0;
            bool named = false;
            for (const posix_acl_xattr_entry& entry : acl) {
                if (entry.e_tag == ACL_USER || entry.e_tag == ACL_GROUP || entry.e_tag == ACL_GROUP_OBJ) {
                    mask |= entry.e_perm;
                    named |= entry.e_tag != ACL_GROUP_OBJ;
                }
            }
            if (named) {
                acl.push_back({ACL_MASK, (__le16)mask, (__le32)ACL_UNDEFINED_ID});
            }
            std::sort(acl.begin(), acl.end(), [](const posix_acl_xattr_entry& a, const posix_acl_xattr_entry& b) {
                return a.e_tag != b.e_tag ? a.e_tag < b.e_tag : a.e_id < b.e_id;
            });

            std::vector<char> buffer(sizeof(posix_acl_xattr_header) + acl.size() * sizeof(posix_acl_xattr_entry));
            ((posix_acl_xattr_header*)buffer.data())->a_version = POSIX_ACL_XATTR_VERSION;
            memcpy(buffer.data() + sizeof(posix_acl_xattr_header), acl.data(), acl.size() * sizeof(posix_acl_xattr_entry));
            if (lsetxattr(path.c_str(), "system.posix_acl_access", buffer.data(), buffer.size(), 0) < 0) {
                Die("setxattr %s: %m", path.c_str());
            }
        }

      public:
        FilePermissions(const vector<string>& ruleStrings) {
            for (const std::string& rule : ruleStrings) {
                size_t colon = rule.find(':');
                int perm = colon == std::string::npos ? 0 : permFromString(rule.substr(colon + 1));
                rules.push_back({rule.substr(0, colon), perm});
            }
        }

        /// Jails sharing a box take turns, on a lock out of the programs' reach, since both rewrite the shared entries' ACLs
        void applyRules(uid_t uid, int lockFd) {
            if (flock(lockFd, LOCK_EX) < 0) {
                Die("flock: %m");
            }

            /// The last rule naming a path wins
            struct Wanted {
                int perm;
                bool mayVanish;
            };
            std::map<std::string, Wanted> wanted;
            for (const Rule& rule : rules) {
                for (const std::string& path : expandPath(rule.pattern)) {
                    wanted[path] = {rule.perm, hasWildcards(rule.pattern)};
                }
            }

            for (const auto& [path, want] : wanted) {
                bool topLevel = path.find('/') == std::string::npos;
                Msg(2, "ACL: %s gets %d for uid %d\n", path.c_str(), want.perm, uid);
                setAcl(path, uid, want.perm, topLevel, want.mayVanish);
            }
            close(lockFd);
        }
    };
};
