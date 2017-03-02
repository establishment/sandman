#include "config.hpp"
#include "json/json"

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
	obj.blockQuota = this->operator[]("blockQuota").Get<int>();
	obj.inodeQuota = this->operator[]("inodeQuota").Get<int>();
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
	obj.useDefaultRules = this->operator[]("useDefaultRules").Get<int>();
	obj.passEnvironment = this->operator[]("passEnvironment").Get<int>();
	obj.rules = this->operator[]("rules").Get<vector<string>>();
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
	obj.rules = this->operator[]("rules").Get<vector<string>>();
	obj.fullPermissionsOverFolder = this->operator[]("fullPermissionsOverFolder").Get<int>();
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
	obj.mode = this->operator[]("mode").Get<int>();
	obj.boxId = this->operator[]("boxId").Get<int>();
	obj.processId = this->operator[]("processId").Get<int>();
	obj.verboseLevel = this->operator[]("verboseLevel").Get<int>();
	obj.metaFile = this->operator[]("metaFile").Get<string>();
	obj.cpuTimeLimitMs = this->operator[]("cpuTimeLimitMs").Get<unsigned long long>();
	obj.wallTimeLimitMs = this->operator[]("wallTimeLimitMs").Get<unsigned long long>();
	obj.extraTimeMs = this->operator[]("extraTimeMs").Get<unsigned long long>();
	obj.checkIntervalMs = this->operator[]("checkIntervalMs").Get<unsigned long long>();
	obj.memoryLimitKB = this->operator[]("memoryLimitKB").Get<int>();
	obj.stackLimitKB = this->operator[]("stackLimitKB").Get<int>();
	obj.redirectStdin = this->operator[]("redirectStdin").Get<string>();
	obj.redirectStdout = this->operator[]("redirectStdout").Get<string>();
	obj.redirectStderr = this->operator[]("redirectStderr").Get<string>();
	obj.execDirectory = this->operator[]("execDirectory").Get<string>();
	obj.fileSizeLimitKB = this->operator[]("fileSizeLimitKB").Get<int>();
	obj.maxProcesses = this->operator[]("maxProcesses").Get<int>();
	obj.shareNetwork = this->operator[]("shareNetwork").Get<int>();
	obj.swapPipeOpenOrder = this->operator[]("swapPipeOpenOrder").Get<bool>();
	obj.runCommand = this->operator[]("runCommand").Get<string>();
	obj.environment = this->operator[]("environment").Get<::ProcessConfig::Environment>();
	obj.dirRules = this->operator[]("dirRules").Get<::ProcessConfig::DirRules>();
	obj.diskQuota = this->operator[]("diskQuota").Get<::ProcessConfig::DiskQuota>();
	obj.filePermissions = this->operator[]("filePermissions").Get<::ProcessConfig::FilePermissions>();
	return obj;
}
}  //namespace AutoJson


