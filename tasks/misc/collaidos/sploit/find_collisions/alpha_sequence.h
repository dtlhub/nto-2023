#pragma once

#include <bits/stdc++.h>
using namespace std;

class AlphaSequence {
   public:
    AlphaSequence(size_t _from, size_t _to);

    class Iterator {
       private:
        vector<int> order;

       public:
        Iterator(size_t value);
        size_t operator*() const;
        Iterator operator++();

        bool operator==(const Iterator& other) const;
        bool operator!=(const Iterator& other) const;
    };

    Iterator begin();
    Iterator end();

   private:
    size_t from, to;
};
