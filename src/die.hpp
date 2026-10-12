#pragma once

#include "cpp-base/logger.hpp"

namespace Base {
/// Two strings and a third argument would pick Die(field, message, isJson) over the printf form, so such a call doesn't compile
template <typename T>
void Die(const char* format, const char* argument, T other) = delete;
}  // namespace Base
