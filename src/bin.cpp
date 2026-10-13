#include <fcntl.h>
#include <sys/stat.h>

#include <string>
#include <vector>

#include "die.hpp"
#include "lib.hpp"

#include "cxxopts/cxxopts.hpp"

using namespace std;

/// The time limits as the command line gives them, in seconds
struct TimeLimits {
    double cpuTimeS;
    double wallTimeS;
};

cxxopts::Options AddOptions(ProcessConfig& config, TimeLimits& timeLimits) {
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
        "meta", "Output run stats to specified file (none = not written)",
        cxxopts::value<string>(config.metaFile)->default_value("")->implicit_value("metares.txt"), "FILE");

    options.add_options("Time")(  //
        "t,time", "CPU time limit (seconds, real)",
        cxxopts::value<double>(timeLimits.cpuTimeS)->default_value("0.0")->implicit_value("1.0"), "LIMIT-S");

    options.add_options("Time")(  //
        "wall-time", "Wall clock time limit (seconds, real)",
        cxxopts::value<double>(timeLimits.wallTimeS)->default_value("0.0")->implicit_value("1.0"), "LIMIT-S");

    options.add_options("Memory")(  //
        "m,memory", "Limit memory to <SIZE> in KB (0 is unlimited)",
        cxxopts::value<int>(config.memoryLimitKB)->default_value("0")->implicit_value("131072"), "SIZE");

    options.add_options("Memory")(  //
        "stack", "Limit stack size to <SIZE> in KB (0 is unlimited)",
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
        "interactive", "Open stdout before stdin, so two jails talking over fifos don't wait for each other's open");

    options.add_options("Rules")(  //
        "include-dir", "Bind the host directory of that path into the jail, read-only; skipped if the host has none",
        cxxopts::value<vector<string>>(config.includeDirs), "DIR");

    options.add_options("Rules")(  //
        "env", "Set environment variable <var> to <val>, or inherit isolate's own value without <val>. Nothing else is passed, and the command is searched on the PATH given here.",
        cxxopts::value<vector<string>>(config.environmentRules), "var[=val]");

    options.add_options("Rules")(  //
        "permission", "Give the program <perm> on <file>, a path or glob under the box; no <perm> takes its access away. Applied in the given order.",
        cxxopts::value<vector<string>>(config.permissionRules), "file[:perm(rwx string)]");

    options.add_options("Rules")(  //
        "quota-blocks", "Limit what each of the box's users may own on its filesystem to <arg> KB (needs usrquota)",
        cxxopts::value<int>(config.quotaBlocksKB)->default_value("0"));

    options.add_options("Rules")(  //
        "quota-inodes", "Limit what each of the box's users may own on its filesystem to <arg> files",
        cxxopts::value<int>(config.quotaInodes)->default_value("0"));

    options.add_options("Rules")(  //
        "file-size", "Max size (in KB) of files that can be created (0 is unlimited)",
        cxxopts::value<int>(config.fileSizeLimitKB)->default_value("0"), "SIZE");

    options.add_options("Rules")(  //
        "chdir", "Change directory to <DIR> before executing the program", cxxopts::value<string>(config.execDirectory),
        "DIR");

    options.add_options("Rules")(  //
        "processes", "Cap on the processes and threads (0 is unlimited)",
        cxxopts::value<int>(config.maxProcesses)->default_value("32"), "max");

    options.add_options()("i,init", "Initialize sandbox");
    options.add_options()("r,run", "Run given command in sandbox (positional arguments)");
    options.add_options()("cleanup", "Clean up sandbox");
    options.add_options()("h,help", "");

    return options;
}

ProcessConfig ParseCommandLineArguments(int argc, char** argv) {
    ProcessConfig config;
    TimeLimits timeLimits;
    auto options = AddOptions(config, timeLimits);

    options.add_options()("positional", " -- run command", cxxopts::value<vector<string>>(config.runCommand));
    options.parse_positional("positional");
    try {
        options.parse(argc, argv);

        if (options.count("help")) {
            std::cout << options.help({"", "Config", "Time", "Memory", "Redirects", "Rules"}) << std::endl;
            exit(0);
        }
    } catch (const cxxopts::OptionException& e) {
        std::cout << "error parsing options: " << e.what() << "\n";
        exit(1);
    }

    config.swapPipeOpenOrder = options.count("interactive");
    if (options.count("init")) {
        config.mode = ProcessConfig::kInit;
    }
    if (options.count("run")) {
        config.mode = ProcessConfig::kRun;
    }
    if (options.count("cleanup")) {
        config.mode = ProcessConfig::kCleanup;
    }

    config.cpuTimeLimitMs = 1000.0 * timeLimits.cpuTimeS;
    config.wallTimeLimitMs = 1000.0 * timeLimits.wallTimeS;

    return config;
}

int main(int argc, char** argv) {
    /// Root's log, so nobody else may write to it, whatever mode an earlier isolate left it with
    int logFd = open("/eval/isolate.log", O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0640);
    if (logFd < 0 || fchmod(logFd, 0640) < 0) {
        Die("open /eval/isolate.log: %m");
    }
    Base::die_fd = logFd;

    auto config = ParseCommandLineArguments(argc, argv);

    if (config.mode == ProcessConfig::kUnspecified) {
        Die("Please specify an isolate command (e.g. --init, --run).");
    }

    if (geteuid()) {
        Die("Must be started as root");
    }

    if (config.mode == ProcessConfig::kRun && config.runCommand.empty()) {
        Die("--run mode requires a command to run");
    }

    Jailer jailer(config);
    jailer.Start();

    exit(0);
}
