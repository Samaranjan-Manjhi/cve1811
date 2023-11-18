#include <iostream>
#include <fstream>
#include <sstream>
#include <sqlite3.h>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

using namespace std;

class CVEDataProcessor {
public:
    CVEDataProcessor(const std::string& database_file = "/home/escan/aaaa/cvebintool/tables/cve_cpp_ex.db")
        : connection_(nullptr), database_file_(database_file) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }

    ~CVEDataProcessor() {
        curl_global_cleanup();
    }

    void refresh() {
        initDatabase();
        updateExploits();
    }

private:
    sqlite3* connection_;
    std::string database_file_;

    std::string downloadData(const std::string& url) {
        std::string data;
        CURL* curl = curl_easy_init();

        if (curl) {
            CURLcode res;
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                std::cerr << "Failed to download data: " << curl_easy_strerror(res) << std::endl;
            }

            curl_easy_cleanup(curl);
        }

        return data;
    }

    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output) {
        size_t total_size = size * nmemb;
        output->append(static_cast<char*>(contents), total_size);
        return total_size;
    }

    void dbOpen() {
        if (connection_ == nullptr) {
            int rc = sqlite3_open(database_file_.c_str(), &connection_);
            if (rc != SQLITE_OK) {
                std::cout << "Cannot open database: " << sqlite3_errmsg(connection_) << std::endl;
                sqlite3_close(connection_);
            }
        }
    }

    void initDatabase() {
        dbOpen();
        char* errMsg = nullptr;

        const char* exploitTableCreate = R"(
            CREATE TABLE IF NOT EXISTS cve_exploited (
                cve_number TEXT,
                product TEXT,
                description TEXT,
                PRIMARY KEY(cve_number)
            )
        )";

        sqlite3_exec(connection_, exploitTableCreate, 0, 0, &errMsg);

        if (errMsg != nullptr) {
            std::cout << "Error creating table: " << errMsg << std::endl;
            sqlite3_free(errMsg);
        }

        sqlite3_close(connection_);
    }

    void updateExploits() {
        // Get the latest list of vulnerabilities from cisa.gov
        std::string url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
        std::string data = downloadData(url);

        if (!data.empty()) {
            nlohmann::json root = nlohmann::json::parse(data);

            std::vector<std::tuple<std::string, std::string, std::string>> exploitList;

            for (const auto& cve : root["vulnerabilities"]) {
                std::string cveID = cve["cveID"].get<std::string>();
                std::string product = cve["product"].get<std::string>();
                std::string shortDescription = cve["shortDescription"].get<std::string>();
                exploitList.push_back(std::make_tuple(cveID, product, shortDescription));
		          std::cout << cveID << ", " << product << ", " << shortDescription << std::endl;
                populateExploitDB(exploitList);
            }

            //populateExploitDB(exploitList);
        }
    }

    void populateExploitDB(const std::vector<std::tuple<std::string, std::string, std::string>>& exploitList) {
        dbOpen();
        sqlite3_stmt* stmt;

        for (const auto& exploit : exploitList) {
            std::string insertExploitQuery = "INSERT OR REPLACE INTO cve_exploited VALUES (?, ?, ?)";
            std::cout << "SQL Statement: " << insertExploitQuery << std::endl;

            int rc = sqlite3_prepare_v2(connection_, insertExploitQuery.c_str(), -1, &stmt, nullptr);
            std::cout << "Prepare Statement Result: " << rc << std::endl;

            if (rc != SQLITE_OK) {
                std::cout << "Failed to prepare SQL statement for cve_exploited: " << sqlite3_errmsg(connection_) << std::endl;
                return;
            }

            // Bind parameters
            rc = sqlite3_bind_text(stmt, 1, std::get<0>(exploit).c_str(), -1, SQLITE_STATIC);
            std::cout << "Bind Parameter 1 Result: " << rc << std::endl;

            rc = sqlite3_bind_text(stmt, 2, std::get<1>(exploit).c_str(), -1, SQLITE_STATIC);
            std::cout << "Bind Parameter 2 Result: " << rc << std::endl;

            rc = sqlite3_bind_text(stmt, 3, std::get<2>(exploit).c_str(), -1, SQLITE_STATIC);
            std::cout << "Bind Parameter 3 Result: " << rc << std::endl;

            // Execute statement
            rc = sqlite3_step(stmt);
            std::cout << "Step Result: " << rc << std::endl;

            if (rc != SQLITE_DONE) {
                std::cout << "Failed to execute SQL statement for cve_exploited: " << sqlite3_errmsg(connection_) << std::endl;
            }

            // Reset and finalize the statement
            rc = sqlite3_reset(stmt);
            std::cout << "Reset Result: " << rc << std::endl;

            rc = sqlite3_finalize(stmt);
            std::cout << "Finalize Result: " << rc << std::endl;
        }

        sqlite3_close(connection_);
    }
};

int main() {
    CVEDataProcessor processor;
    processor.refresh();

    return 0;
}

