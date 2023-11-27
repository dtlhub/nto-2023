#include <algorithm>
#include <iostream>
#include <string>
#include <unordered_set>
#include <vector>

struct Account {
    std::string username;
    std::string password;

    static void validate(const std::string& s) {
        if (s.size() >= 16) {
            throw std::runtime_error("String is too long");
        }

        if (!std::all_of(s.begin(), s.end(), [](unsigned char c) {
                return std::isalnum(c) || c == '_' || c == '-' || c == '.';
            })) {
            throw std::runtime_error("String has forbidden characters");
        }
    }
};


class AccountDatabase {
public:
    constexpr static int MAX_ENTRIES = 30'000;

    AccountDatabase() : accounts(0) {}

    void add_user(const Account& account) {
        accounts.emplace_back(account);
    }

    size_t unique_users() const {
        return count_unique_values(accounts, [](const Account& account) { return account.username; });
    }

    size_t unique_passwords() const {
        return count_unique_values(accounts, [](const Account& account) { return account.password; });
    }

    size_t size() const {
        return accounts.size();
    }

private:
    template <typename T, typename F>
    static size_t count_unique_values(const std::vector<T>& objects, F&& property_getter) {
        std::unordered_set<decltype(property_getter(std::declval<T>()))> values;
        for (const auto& object : objects) {
            values.insert(property_getter(object));
        }
        return values.size();
    }

    std::vector<Account> accounts;
};

void fill_database(AccountDatabase& database) {
    std::string username, password;
    while (database.size() < AccountDatabase::MAX_ENTRIES && (std::cin >> username)) {
        Account::validate(username);
        std::cin >> password;
        Account::validate(password);
        database.add_user({.username = username, .password = password});
    }
}

int main() {
    std::ios_base::sync_with_stdio(false);
    std::cin.tie(nullptr);

    AccountDatabase accounts;
    try {
        fill_database(accounts);
    } catch (const std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
        return 1; 
    }

    std::cout << "Unique users: " << accounts.unique_users() << '\n';
    std::cout << "Unique passwords: " << accounts.unique_passwords() << std::endl;
}