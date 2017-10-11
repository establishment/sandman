#include <getopt.h>

#include <cstring>

#include <string>
#include <vector>

#include "config_json_impl.hpp"
#include "lib.hpp"

#include "cpp-base/logger.hpp"
#include "cpp-base/string_utils.hpp"
#include "cxxopts/cxxopts.hpp"

using namespace std;
using namespace Base;

char** CopyArguments(int argc, char** argv) {
    char** new_argv = (char**)malloc((argc + 1) * sizeof(char*));
    new_argv[argc] = nullptr;
    for (int i = 0; i < argc; i += 1) {
        int len = strlen(argv[i]);
        char* txt = (char*)malloc(len * sizeof(char));
        for (int j = 0; j < len; j += 1) {
            txt[j] = argv[i][j];
        }
        txt[len] = '\0';
        new_argv[i] = txt;
    }

    return new_argv;
}

void DeleteArgumentsCopy(char** argv) {
    char** start = argv;
    while (*argv != nullptr) {
        delete *argv;
        argv++;
    }

    delete start;
}

struct CommandLineConfig : public ProcessConfig {
    double cpuTimeLimitS;
    double wallTimeLimitS;
    double extraTimeS;
    double checkIntervalS;
};

vector<string> all_options = {
    "box-id",    "process-id", "verbose",      "meta",         "time",      "wall-time",       "extra-time",
    "memory",    "stack",      "stdin",        "stdout",       "stderr",    "interactive",     "full-env",
    "env",       "permission", "quota-blocks", "quota-inodes", "file-size", "chdir",           "share-net",
    "processes", "init",       "run",          "cleanup",      "help",      "legacy-meta-json"};

int LevenshteinDistance(const string& a, const string& b) {
    vector<vector<int>> d(a.size() + 1, vector<int>(b.size() + 1, 0));
    for (int i = 1; i <= (int)a.size(); i += 1) {
        d[i][0] = i;
    }

    for (int i = 1; i <= (int)b.size(); i += 1) {
        d[0][i] = i;
    }

    for (int i = 1; i <= (int)a.size(); i += 1) {
        for (int j = 1; j <= (int)b.size(); j += 1) {
            d[i][j] = min({d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] == b[j - 1] ? 0 : 1)});
        }
    }

    return d[a.size()][b.size()];
}

string ClosestOption(const string& wrong_option) {
    int mn_distance = 1e9;
    string result = "";

    for (const string& option : all_options) {
        vector<string> small_words;
        string current_word = "";
        for (char itr : option) {
            if (itr == '-') {
                small_words.push_back(current_word);
                current_word = "";
            } else {
                current_word += itr;
            }
        }

        small_words.push_back(current_word);
        vector<int> perm;
        for (int i = 0; i < (int)small_words.size(); i += 1) {
            perm.push_back(i);
        }

        do {
            string new_option = "";
            for (auto itr : perm) {
                new_option += small_words[itr] + "-";
            }
            new_option.pop_back();
            auto current_distance = LevenshteinDistance(wrong_option, new_option);
            if (current_distance < mn_distance) {
                mn_distance = current_distance;
                result = option;
            }
        } while (next_permutation(perm.begin(), perm.end()));
    }

    return result;
}

cxxopts::Options AddOptions(CommandLineConfig& config) {
    cxxopts::Options options("SANDbox MANager");

    options.add_options("Config")(  //
        "b,box-id", "When multiple sandboxes are used in parallel, each must get a unique ID",
        cxxopts::value<int>(config.boxId)->default_value("0"), "ID");

    options.add_options("Config")(  //
        "p,process-id", "Run more tasks inside a sandbox but in different cgroups",
        cxxopts::value<int>(config.processId)->default_value("0"), "PROCESS ID");

    options.add_options("Config")(  //
        "v,verbose", "Be verbose (increase value for bigger verbosity)",
        cxxopts::value<int>(config.verboseLevel)->default_value("0")->implicit_value("+1"));

    options.add_options("Config")(  //
        "meta", "Output run stats to specified file (empty = stdout)",
        cxxopts::value<string>(config.metaFile)->default_value("")->implicit_value("metares.txt"), "FILE");

    options.add_options("Time")(  //
        "t,time", "Run time limit (seconds, real)",
        cxxopts::value<double>(config.cpuTimeLimitS)->default_value("0.0")->implicit_value("1.0"), "LIMIT-S");

    options.add_options("Time")(  //
        "wall-time", "Wall clock time limit (seconds, real)",
        cxxopts::value<double>(config.wallTimeLimitS)->default_value("0.0")->implicit_value("1.0"), "LIMIT-S");

    options.add_options("Time")(  //
        "extra-time", "Extra time before which a timing-out program is not yet killed (seconds, real)",
        cxxopts::value<double>(config.extraTimeS)->default_value("0.0")->implicit_value("0.1"), "LIMIT-S");

    options.add_options("Memory")(  //
        "m,memory", "Limit address space to <SIZE> in KB (0 is unlimited)",
        cxxopts::value<int>(config.memoryLimitKB)->default_value("0")->implicit_value("131072"), "SIZE");

    options.add_options("Memory")(  //
        "stack", "Limit stack size to <SIZE> in KB (0 in unlimited)",
        cxxopts::value<int>(config.stackLimitKB)->default_value("0")->implicit_value("131072"), "SIZE");

    options.add_options("Redirects")(  //
        "stdin", "Redirect stdin to <FILE> (empty = no redirect)",
        cxxopts::value<string>(config.redirectStdin)->default_value("")->implicit_value("stdin.txt"), "FILE");

    options.add_options("Redirects")(  //
        "stdout", "Redirect stdout to <FILE> (empty = no redirect)",
        cxxopts::value<string>(config.redirectStdout)->default_value("")->implicit_value("stdout.txt"), "FILE");

    options.add_options("Redirects")(  //
        "stderr", "Redirect stderr to <FILE> (empty = no redirect)",
        cxxopts::value<string>(config.redirectStderr)->default_value("")->implicit_value("stderr.txt"), "FILE");

    options.add_options("Redirects")(  //
        "interactive",
        "Swap stdin and stdout open order. "
        "(Usefull for interactive problems so that the processes don't enter a fifo wait loop)");

    options.add_options("Rules")(  //
        "include-dir", "Mound target dir inside isolated process, read/execute.",
        cxxopts::value<vector<ProcessConfig::DirRules::DirRule>>(config.dirRules.rules));

    options.add_options("Rules")(  //
        "full-env", "Inherit full environment of the parent process");

    options.add_options("Rules")(  //
        "env", "Chnage environment variable <var> to <val> if <val> is provided. Else inherit the value.",
        cxxopts::value<vector<string>>(config.environment.rules), "var[=val(inherited)]");

    options.add_options("Rules")(  //
        "permission", "Set permissions <perm> to <file>. By default perm is equal to none. The permisions are applied in the given order.",
        cxxopts::value<vector<string>>(config.filePermissions.rules), "file[:perm(rxw string, default:\"\")");

    options.add_options("Rules")(  //
        "quota-blocks", "Set disk quota to <arg> blocks",
        cxxopts::value<int>(config.diskQuota.blockQuota)->default_value("0"));

    options.add_options("Rules")(  //
        "quota-inodes", "Set disk quota to <arg> inodes",
        cxxopts::value<int>(config.diskQuota.blockQuota)->default_value("0"));

    options.add_options("Rules")(  //
        "file-size", "tMax size (in KB) of files that can be created(0 is unlimited)",
        cxxopts::value<int>(config.fileSizeLimitKB)->default_value("0"), "SIZE");

    options.add_options("Rules")(  //
        "chdir", "Change directory to <DIR> before executing the program", cxxopts::value<string>(config.execDirectory),
        "DIR");

    options.add_options("Rules")(  //
        "share-net", "Share network namespace with the parent process");

    options.add_options("Rules")(  //
        "processes", "Enable multiple processes (at most <max> of them) (0 is unlimited)",
        cxxopts::value<int>(config.maxProcesses)->default_value("1")->implicit_value("0"), "max");

    options.add_options("Rules")(  //
        "legacy-meta-json", "Print meta file in old format");

    options.add_options()("i,init", "Initialize sandbox");
    options.add_options()("r,run", "Run given command in sandbox (positional arguments)");
    options.add_options()("cleanup", "Clean up sandbox");
    options.add_options()("h,help", "");

    return options;
}

ProcessConfig ParseCommandLineArguments(int argc, char** argv) {
    CommandLineConfig config;
    auto options = AddOptions(config);

    vector<string> positional;
    options.add_options()("positional", " -- run command", cxxopts::value<vector<string>>(positional));

    options.parse_positional("positional");
    try {
        options.parse(argc, argv);

        if (options.count("help")) {
            std::cout << options.help({"", "Config", "Time", "Memory", "Redirects", "Rules"}) << std::endl;
            exit(0);
        }
    } catch (const cxxopts::option_not_exists_exception& e) {
        auto GetOption = [](const string& exception_message) {
            string result = "";
            bool quoted = false;
            for (char32_t  c : exception_message) {
                if (c == 4294967266) {
                    quoted = false;
                }               

                if (quoted) {
                    result += c;
                }

                if (c == 4294967192) {
                    quoted = true;
                }
            }

            return result;
        };
        
        
        std::cout << e.what() << u8". Did you mean ‘" << ClosestOption(GetOption(e.what())) << u8"’?\n";
        exit(1);
    } catch (const cxxopts::OptionException& e) {
        std::cout << "error parsing options: " << e.what() << "\n";
        exit(1);
    }

    ProcessConfig p_config;
    p_config = config;
   
    if (options.count("interactive")) {
        p_config.swapPipeOpenOrder = true;
    }

    if (options.count("full-env")) {
        p_config.environment.passEnvironment = true;
    }

    if (options.count("share-net")) {
        p_config.shareNetwork = true;
    }

    if (options.count("legacy-meta-json")) {
        p_config.legacyMetaJson = true;
    }

    if (options.count("init")) {
        p_config.mode = ProcessConfig::kInit;
    }

    if (options.count("run")) {
        p_config.mode = ProcessConfig::kRun;
    }

    if (options.count("cleanup")) {
        p_config.mode = ProcessConfig::kCleanup;
    }

    /// convert times to ms
    p_config.cpuTimeLimitMs = 1000.0 * config.cpuTimeLimitS;
    p_config.wallTimeLimitMs = 1000.0 * config.wallTimeLimitS;
    p_config.extraTimeMs = 1000.0 * config.extraTimeS;

    /// add positional arguments
    for (const string& word : positional) {
        p_config.runCommand += "\"" + word + "\"" + " ";
    }

    return p_config;
}

int main(int argc, char** argv) {
    auto config = ParseCommandLineArguments(argc, argv);

    if (config.mode == ProcessConfig::kUnspecified) {
        Die("Please specify an isolate command (e.g. --init, --run).");
    }

    if (geteuid()) {
        Die("Must be started as root");
    }

    if (config.mode == ProcessConfig::kRun) {
        if (config.runCommand == "") {
            Die("--run mode requires a command to run");
        }
    }
    if (config.mode != ProcessConfig::kInit && config.mode != ProcessConfig::kRun &&
        config.mode != ProcessConfig::kCleanup) {
        Die("Internal error: mode mismatch");
    }

    DieLogToFile("/eval/isolate.log");

    Jailer jailer(config, argv + optind);  /// share the stack size with the isolated process.);
    jailer.Start();

    exit(0);
}
