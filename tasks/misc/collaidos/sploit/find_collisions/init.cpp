#include "constants.h"
#include "helpers.h"
#include "init.h"

#include <bits/stdc++.h>
using namespace std;

class GuessingException : std::exception {
   public:
    GuessingException(const string& msg) : message(msg) {}
    const char* what() const noexcept { return message.c_str(); }

   private:
    string message;
};

size_t guess_multipler(size_t first_multiplier, size_t result) {
    if (first_multiplier == 0) {
        throw GuessingException("Can't divide by zero");
    }

    // Simple check
    size_t second_multiplier = result / first_multiplier;
    if (second_multiplier * first_multiplier == result) {
        return second_multiplier;
    }

    // Guessing second multiplier bit-by-bit
    second_multiplier = 0;
    for (size_t i = 0; i < 64; i++) {
        size_t bit = 1LL << i;

        size_t if_set = (second_multiplier | bit);
        size_t if_unset = second_multiplier;

        if (((if_set * first_multiplier) & bit) == (result & bit)) {
            second_multiplier = if_set;
        } else if (((if_unset * first_multiplier) & bit) == (result & bit)) {
            second_multiplier = if_unset;
        } else {
            throw GuessingException("Unable to guess :(");
        }
    }
    return second_multiplier;
}

tuple<uint8_t, uint64_t, size_t> init_generator() {
    cerr << hex;

    uint64_t first_goal = gen_rnd_size_t_str(8), second_goal = gen_rnd_size_t_str(7);
    uint64_t goal_hash = full_hash(first_goal, second_goal, 15);
    string goal_str = parts_to_str(first_goal, second_goal);
    assert(goal_hash == std_hasher(goal_str));
    cerr << "{*} hash(" << goal_str << ") = 0x" << goal_hash << " [GOAL]" << endl;

    uint8_t keep_byte = first_stage(first_goal) >> 56;
    uint64_t goal_after_second_stage = unshift(guess_multipler(mul, unshift(goal_hash)));
    uint64_t goal_in_second_stage = guess_multipler(mul, goal_after_second_stage);
    cerr << "{*} keep_byte = 0x" << (uint64_t) keep_byte << endl;
    cerr << "{*} goal_after_second_stage = 0x" << goal_after_second_stage << endl;
    cerr << "{*} goal_in_second_stage = 0x" << goal_in_second_stage << endl;

    return {keep_byte, goal_in_second_stage, goal_hash};
}
