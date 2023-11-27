#include "alpha_sequence.h"
#include "constants.h"

#include <bits/stdc++.h>
using namespace std;

AlphaSequence::AlphaSequence(size_t _from, size_t _to) : from(_from), to(_to) {}

AlphaSequence::Iterator::Iterator(size_t value) {
    order.assign(8, -1);
    size_t i = 0;
    while (value != 0) {
        order[i] = value % ALPHA.size();
        ++i;
        value /= ALPHA.size();
    }
}

size_t AlphaSequence::Iterator::operator*() const {
    size_t result = 0;
    size_t i = 0;
    while (i < order.size() && order[i] != -1) {
        result |= ((size_t)ALPHA[order[i]]) << (i * 8LL);
        i++;
    }
    return result;
}
AlphaSequence::Iterator AlphaSequence::Iterator::operator++() {
    size_t i = 0;
    while (++order[i] == ALPHA.size()) {
        order[i] = 0;
        ++i;
    }
    return *this;
}

bool AlphaSequence::Iterator::operator==(const Iterator& other) const {
    for (size_t i = 0; i < order.size(); i++) {
        if (order[i] != other.order[i]) {
            return false;
        }
    }
    return true;
}
bool AlphaSequence::Iterator::operator!=(const Iterator& other) const { return !operator==(other); }

AlphaSequence::Iterator AlphaSequence::begin() { return Iterator(from); }
AlphaSequence::Iterator AlphaSequence::end() { return Iterator(to); }
