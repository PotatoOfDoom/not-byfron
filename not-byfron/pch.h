#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <unordered_map>
#include <mutex>
#include <queue>

#ifdef _DEBUG
#define PRINTD(_Format,...) printf(_Format,__VA_ARGS__)
#else
#define PRINTD(_Format,...) (void)(_Format, __VA_ARGS__)
#endif