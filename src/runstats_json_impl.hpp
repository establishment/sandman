#include "runstats.hpp"
#include "json/json.cpp"

namespace AutoJson {
template<>
AutoJson::Json::Json(__attribute__((unused)) const ::RunStats::ResultCode& rhs) : type(JsonType::OBJECT), content(new std::map<std::string, Json>()) {
	(*this) = int(rhs);
}

template<>
AutoJson::Json::operator ::RunStats::ResultCode() {
	::RunStats::ResultCode obj;
	obj = ::RunStats::ResultCode((*this).Get<int>());
	return obj;
}
}  //namespace AutoJson

namespace AutoJson {
template<>
AutoJson::Json::Json(const ::RunStats::TimeStat& rhs) : type(JsonType::OBJECT), content(new std::map<std::string, Json>()) {
	(*this)["wallTimeMs"] = rhs.wallTimeMs;
	(*this)["cpuTimeMs"] = rhs.cpuTimeMs;
	(*this)["userTimeMs"] = rhs.userTimeMs;
	(*this)["systemTimeMs"] = rhs.systemTimeMs;
}

template<>
AutoJson::Json::operator ::RunStats::TimeStat() {
	::RunStats::TimeStat obj;
	obj.wallTimeMs = (*this)["wallTimeMs"].Get<unsigned long long>();
	obj.cpuTimeMs = (*this)["cpuTimeMs"].Get<unsigned long long>();
	obj.userTimeMs = (*this)["userTimeMs"].Get<unsigned long long>();
	obj.systemTimeMs = (*this)["systemTimeMs"].Get<unsigned long long>();
	return obj;
}
}  //namespace AutoJson

namespace AutoJson {
template<>
AutoJson::Json::Json(const ::RunStats& rhs) : type(JsonType::OBJECT), content(new std::map<std::string, Json>()) {
	(*this)["timeStat"] = rhs.timeStat;
	(*this)["memoryKB"] = rhs.memoryKB;
	(*this)["rssPeak"] = rhs.rssPeak;
	(*this)["cswVoluntary"] = rhs.cswVoluntary;
	(*this)["cswForced"] = rhs.cswForced;
	(*this)["softPageFaults"] = rhs.softPageFaults;
	(*this)["hardPageFaults"] = rhs.hardPageFaults;
	(*this)["nrSysCalls"] = rhs.nrSysCalls;
	(*this)["lastSysCall"] = rhs.lastSysCall;
	(*this)["terminalSignal"] = rhs.terminalSignal;
	(*this)["exitCode"] = rhs.exitCode;
	(*this)["processWasKilled"] = rhs.processWasKilled;
	(*this)["resultCode"] = rhs.resultCode;
	(*this)["internalMessage"] = rhs.internalMessage;
	(*this)["version"] = rhs.version;
}

template<>
AutoJson::Json::operator ::RunStats() {
	::RunStats obj;
	obj.timeStat = (*this)["timeStat"].Get<::RunStats::TimeStat>();
	obj.memoryKB = (*this)["memoryKB"].Get<size_t>();
	obj.rssPeak = (*this)["rssPeak"].Get<long int>();
	obj.cswVoluntary = (*this)["cswVoluntary"].Get<long int>();
	obj.cswForced = (*this)["cswForced"].Get<long int>();
	obj.softPageFaults = (*this)["softPageFaults"].Get<size_t>();
	obj.hardPageFaults = (*this)["hardPageFaults"].Get<size_t>();
	obj.nrSysCalls = (*this)["nrSysCalls"].Get<int>();
	obj.lastSysCall = (*this)["lastSysCall"].Get<int>();
	obj.terminalSignal = (*this)["terminalSignal"].Get<int>();
	obj.exitCode = (*this)["exitCode"].Get<int>();
	obj.processWasKilled = (*this)["processWasKilled"].Get<bool>();
	obj.resultCode = (*this)["resultCode"].Get<::RunStats::ResultCode>();
	obj.internalMessage = (*this)["internalMessage"].Get<std::string>();
	return obj;
}
}  //namespace AutoJson


