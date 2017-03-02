#include <getopt.h>

#include <cstring>

#include <string>

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
        cxxopts::value<string>(config.redirectStdin)->default_value("")->implicit_value("stdout.txt"), "FILE");

    options.add_options("Redirects")(  //
        "stderr", "Redirect stderr to <FILE> (empty = no redirect)",
        cxxopts::value<string>(config.redirectStdin)->default_value("")->implicit_value("stderr.txt"), "FILE");

    options.add_options("Redirects")(  //
        "interactive",
        "Swap stdin and stdout open order. "
        "(Usefull for interactive problems so that the processes don't enter a fifo wait loop)");

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
        cxxopts::value<int>(config.maxProcesses)->default_value("0"), "max");

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
    } catch (const cxxopts::OptionException& e) {
        std::cout << "error parsing options: " << e.what() << std::endl;
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
        p_config.runCommand += word + " ";
    }

    return p_config;
}

int main(int argc, char** argv) {
    auto config = ParseCommandLineArguments(argc, argv);

    DieLogToFile("/eval/isolate.log");
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

    Jailer jailer(config, argv + optind);  /// share the stack size with the isolated process.);
    jailer.Start();

    exit(0);
}
