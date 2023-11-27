#include "helpers.h"
#include "constants.h"

#include <bits/stdc++.h>
using namespace std;

bool is_valid_string(size_t p) {
    bool result = true;
    while (p != 0) {
        result &= isalnum(p & 0xff) || (p & 0xff) == '_' || (p & 0xff) == '-' || (p & 0xff) == '.';
        p >>= 8;
    }
    return result;
}
size_t gen_rnd_size_t_str(int length = 8) {
    if (length > 8) {
        throw invalid_argument("Max size for size_t is 8 bytes");
    }

    size_t res = 0;
    for (int i = 0; i < length; i++) {
        size_t chr = ALPHA[rand() % ALPHA.size()];
        res |= (chr << (i * 8LL));
    }
    return res;
}

size_t get_length(size_t val) {
    int length = 0;
    while (val != 0) {
        ++length;
        val >>= 8;
    }
    return length;
}

string parts_to_str(size_t first, size_t second) {
    string res;
    while (first != 0) {
        res += (char)first & 0xff;
        first >>= 8;
    }
    while (second != 0) {
        res += (char)second & 0xff;
        second >>= 8;
    }
    return res;
}

size_t shift_mix(size_t v) { return v ^ (v >> 47); }
size_t unshift(size_t v) { return shift_mix(v); }

size_t first_stage(size_t p) {
    size_t hash = hash_init;
    size_t data = shift_mix(p * mul) * mul;
    hash ^= data;
    hash *= mul;
    return hash;
}

size_t full_hash(size_t first, size_t second, size_t len) {
    // 0xc6a4a7935bd1e995 = 14313749767032793493
    size_t mul = (((size_t)0xc6a4a793UL) << 32UL) + (size_t)0x5bd1e995UL;
    size_t hash = 0xC70f6907UL ^ (len * mul);

    // First stage
    size_t data = shift_mix(first * mul) * mul;
    hash ^= data;
    hash *= mul;

    // Second stage
    data = second;
    hash ^= data;
    hash *= mul;

    // Here hashese already must be the same
    hash = shift_mix(hash) * mul;
    hash = shift_mix(hash);
    return hash;
}
