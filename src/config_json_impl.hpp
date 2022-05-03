#include "config.hpp"
#include "json/json.cpp"

namespace AutoJson {
template<>
AutoJson::Json::Json(__attribute__((unused)) const ::ProcessConfig::DirRules& rhs) : type(JsonType::OBJECT), content(new std::map<std::string, Json>()) {
}

template<>
AutoJson::Json::operator ::ProcessConfig::DirRules() {
	::ProcessConfig::DirRules obj;
	return obj;
}
}  //namespace AutoJson

namespace AutoJson {
template<>
AutoJson::Json::Json(const ::ProcessConfig::DiskQuota& rhs) : type(JsonType::OBJECT), content(new std::map<std::string, Json>()) {
	(*this)["blockQuota"] = rhs.blockQuota;
	(*this)["inodeQuota"] = rhs.inodeQuota;
}

template<>
AutoJson::Json::operator ::ProcessConfig::DiskQuota() {
	::ProcessConfig::DiskQuota obj;
	obj.blockQuota = (*this)["blockQuota"].Get<int>();
	obj.inodeQuota = (*this)["inodeQuota"].Get<int>();
	return obj;
}
}  //namespace AutoJson

namespace AutoJson {
template<>
AutoJson::Json::Json(const ::ProcessConfig::Environment& rhs) : type(JsonType::OBJECT), content(new std::map<std::string, Json>()) {
	(*this)["useDefaultRules"] = rhs.useDefaultRules;
	(*this)["passEnvironment"] = rhs.passEnvironment;
	(*this)["rules"] = rhs.rules;
}

template<>
AutoJson::Json::operator ::ProcessConfig::Environment() {
	::ProcessConfig::Environment obj;
	obj.useDefaultRules = (*this)["useDefaultRules"].Get<int>();
	obj.passEnvironment = (*this)["passEnvironment"].Get<int>();
	obj.rules = (*this)["rules"].Get<vector<string>>();
	return obj;
}
}  //namespace AutoJson

namespace AutoJson {
template<>
AutoJson::Json::Json(const ::ProcessConfig::FilePermissions& rhs) : type(JsonType::OBJECT), content(new std::map<std::string, Json>()) {
	(*this)["rules"] = rhs.rules;
	(*this)["fullPermissionsOverFolder"] = rhs.fullPermissionsOverFolder;
}

template<>
AutoJson::Json::operator ::ProcessConfig::FilePermissions() {
	::ProcessConfig::FilePermissions obj;
	obj.rules = (*this)["rules"].Get<vector<string>>();
	obj.fullPermissionsOverFolder = (*this)["fullPermissionsOverFolder"].Get<int>();
	return obj;
}
}  //namespace AutoJson

namespace AutoJson {
template<>
AutoJson::Json::Json(__attribute__((unused)) const ::ProcessConfig::Modes& rhs) : type(JsonType::OBJECT), content(new std::map<std::string, Json>()) {
	(*this) = int(rhs);
}

template<>
AutoJson::Json::operator ::ProcessConfig::Modes() {
	::ProcessConfig::Modes obj;
	obj = ::ProcessConfig::Modes((*this).Get<int>());
	return obj;
}
}  //namespace AutoJson

namespace AutoJson {
template<>
AutoJson::Json::Json(const ::ProcessConfig& rhs) : type(JsonType::OBJECT), content(new std::map<std::string, Json>()) {
	(*this)["mode"] = rhs.mode;
	(*this)["boxId"] = rhs.boxId;
	(*this)["processId"] = rhs.processId;
	(*this)["verboseLevel"] = rhs.verboseLevel;
	(*this)["metaFile"] = rhs.metaFile;
	(*this)["cpuTimeLimitMs"] = rhs.cpuTimeLimitMs;
	(*this)["wallTimeLimitMs"] = rhs.wallTimeLimitMs;
	(*this)["extraTimeMs"] = rhs.extraTimeMs;
	(*this)["checkIntervalMs"] = rhs.checkIntervalMs;
	(*this)["memoryLimitKB"] = rhs.memoryLimitKB;
	(*this)["stackLimitKB"] = rhs.stackLimitKB;
	(*this)["redirectStdin"] = rhs.redirectStdin;
	(*this)["redirectStdout"] = rhs.redirectStdout;
	(*this)["redirectStderr"] = rhs.redirectStderr;
	(*this)["execDirectory"] = rhs.execDirectory;
	(*this)["fileSizeLimitKB"] = rhs.fileSizeLimitKB;
	(*this)["maxProcesses"] = rhs.maxProcesses;
	(*this)["shareNetwork"] = rhs.shareNetwork;
	(*this)["swapPipeOpenOrder"] = rhs.swapPipeOpenOrder;
	(*this)["runCommand"] = rhs.runCommand;
	(*this)["environment"] = rhs.environment;
	(*this)["dirRules"] = rhs.dirRules;
	(*this)["diskQuota"] = rhs.diskQuota;
	(*this)["filePermissions"] = rhs.filePermissions;
}

template<>
AutoJson::Json::operator ::ProcessConfig() {
	::ProcessConfig obj;
	obj.mode = (*this)["mode"].Get<int>();
	obj.boxId = (*this)["boxId"].Get<int>();
	obj.processId = (*this)["processId"].Get<int>();
	obj.verboseLevel = (*this)["verboseLevel"].Get<int>();
	obj.metaFile = (*this)["metaFile"].Get<string>();
	obj.cpuTimeLimitMs = (*this)["cpuTimeLimitMs"].Get<unsigned long long>();
	obj.wallTimeLimitMs = (*this)["wallTimeLimitMs"].Get<unsigned long long>();
	obj.extraTimeMs = (*this)["extraTimeMs"].Get<unsigned long long>();
	obj.checkIntervalMs = (*this)["checkIntervalMs"].Get<unsigned long long>();
	obj.memoryLimitKB = (*this)["memoryLimitKB"].Get<int>();
	obj.stackLimitKB = (*this)["stackLimitKB"].Get<int>();
	obj.redirectStdin = (*this)["redirectStdin"].Get<string>();
	obj.redirectStdout = (*this)["redirectStdout"].Get<string>();
	obj.redirectStderr = (*this)["redirectStderr"].Get<string>();
	obj.execDirectory = (*this)["execDirectory"].Get<string>();
	obj.fileSizeLimitKB = (*this)["fileSizeLimitKB"].Get<int>();
	obj.maxProcesses = (*this)["maxProcesses"].Get<int>();
	obj.shareNetwork = (*this)["shareNetwork"].Get<int>();
	obj.swapPipeOpenOrder = (*this)["swapPipeOpenOrder"].Get<bool>();
	obj.runCommand = (*this)["runCommand"].Get<string>();
	obj.environment = (*this)["environment"].Get<::ProcessConfig::Environment>();
	obj.dirRules = (*this)["dirRules"].Get<::ProcessConfig::DirRules>();
	obj.diskQuota = (*this)["diskQuota"].Get<::ProcessConfig::DiskQuota>();
	obj.filePermissions = (*this)["filePermissions"].Get<::ProcessConfig::FilePermissions>();
	return obj;
}
}  //namespace AutoJson


