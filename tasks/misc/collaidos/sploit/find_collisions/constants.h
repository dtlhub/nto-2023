#pragma once

#include <bits/stdc++.h>
using namespace std;

constexpr size_t THREADS = 4;
constexpr size_t REQUIRED_COLLISIONS = 100;

const string ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.";

constexpr size_t TOTAL_WORK = 318644812890625LL;  // len(ALPHA) ** 8
constexpr size_t PER_THREAD = TOTAL_WORK / THREADS;
