#include "alpha_sequence.h"
#include "constants.h"
#include "helpers.h"
#include "init.h"

#include <bits/stdc++.h>
using namespace std;

int main() {
    mutex action_mutex; // Is locked on both cerr & cout
    atomic<size_t> collisions_found{0};

    const auto [keep_byte, goal_in_second_stage, goal_hash] = init_generator();
    cerr << "Going to find " << dec << REQUIRED_COLLISIONS << hex << " strings with hash 0x" << goal_hash << endl;

    vector<thread> threads;
    for (size_t i = 0; i * PER_THREAD < TOTAL_WORK; i++) {
        threads.emplace_back([&, start = i * PER_THREAD, id = i]() {
            AlphaSequence seq(start, min(start + PER_THREAD, TOTAL_WORK));
            for (auto it = seq.begin(); it != seq.end(); ++it) {
                if (collisions_found >= REQUIRED_COLLISIONS) {
                    return;
                }

                if (is_valid_string(*it)) {
                    size_t first = *it;
                    size_t first_stage_result = first_stage(first);
                    if (first_stage_result >> 56 != keep_byte) {
                        continue;
                    }

                    size_t second = goal_in_second_stage ^ first_stage_result;
                    if (is_valid_string(second) && get_length(second) == 7) {
                        string str = parts_to_str(first, second);
                        if (std_hasher(str) == goal_hash) {
                            collisions_found.fetch_add(1);
                            {
                                scoped_lock guard(action_mutex);
                                cout << str << ' ' << str << endl;
                                cerr << "[" << (id < 16 ? "0" : "") << id << "]"
                                     << " {+} hash(" << str << ") = 0x" << std_hasher(str) << dec
                                     << " (" << collisions_found << "/" << REQUIRED_COLLISIONS
                                     << ")" << hex << endl;
                            }
                        }
                    }
                }
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }
}