#pragma once

#include <bits/stdc++.h>
using namespace std;

const hash<string> std_hasher{};

bool is_valid_string(size_t p);

size_t gen_rnd_size_t_str(int length);

size_t get_length(size_t val);
string parts_to_str(size_t first, size_t second);

size_t shift_mix(size_t v);
size_t unshift(size_t v);

const size_t mul = (((size_t)0xc6a4a793UL) << 32UL) + (size_t)0x5bd1e995UL;
const size_t hash_init = 0xC70f6907UL ^ (15 * mul);

size_t first_stage(size_t p);
size_t full_hash(size_t first, size_t second, size_t len);
