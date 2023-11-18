#include <iostream>
#include <fstream>
#include <sstream>
#include <sqlite3.h>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

using namespace std;
using json = nlohmann::json;  // Add this line to use the correct namespace

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
                description TEXT
            )
        )";

        sqlite3_exec(connection_, exploitTableCreate, 0, 0, &errMsg);

        sqlite3_close(connection_);
    }

    void updateExploits() {
        // Get the latest list of vulnerabilities from cisa.gov
        std::string url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
        std::string data = downloadData(url);

        if (!data.empty()) {
            json root = json::parse(data);  // Use json::parse to parse the JSON data

            std::vector<std::tuple<std::string, std::string, std::string>> exploitList;

            for (const auto& cve : root["vulnerabilities"]) {
                std::string cveID = cve["cveID"].get<std::string>();
                std::string product = cve["product"].get<std::string>();
                std::string shortDescription = cve["shortDescription"].get<std::string>();
                exploitList.push_back(std::make_tuple(cveID, product, shortDescription));
//		          populateExploitDB(exploitList);
		          //exploitList.clear();
                std::cout << cveID << ", " << product << ", " << shortDescription << std::endl;
            }

            populateExploitDB(exploitList);
        }
    }

/*    void populateExploitDB(const std::vector<std::tuple<std::string, std::string, std::string>>& exploitList) {
        dbOpen();
        sqlite3_stmt* stmt;

        for (const auto& exploit : exploitList) {
        std::cout << "Inserting data: " << std::get<0>(exploit) << ", " << std::get<1>(exploit) << ", " << std::get<2>(exploit) << std::endl;
        std::string insertExploitQuery = "INSERT OR REPLACE INTO cve_exploited VALUES (?, ?, ?)";
        int rc = sqlite3_prepare_v2(connection_, insertExploitQuery.c_str(), -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
                std::cout <<  "samar Failed to prepare SQL statement for cve_exploited: " << sqlite3_errmsg(connection_) << std::endl;
                return;
         }
         
         cout<< "rc value: " << rc <<endl;

		   std::cout<< std::get<0>(exploit) << endl;
		   std::cout<< std::get<1>(exploit) << endl;
		   std::cout<< std::get<2>(exploit) << endl;

        sqlite3_bind_text(stmt, 1, std::get<0>(exploit).c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, std::get<1>(exploit).c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, std::get<2>(exploit).c_str(), -1, SQLITE_STATIC);

         rc = sqlite3_step(stmt);
         if (rc != SQLITE_DONE) {
             std::cout << "Failed to execute SQL statement for cve_exploited: " << sqlite3_errmsg(connection_) << std::endl;
         }

         sqlite3_finalize(stmt);

        }

        sqlite3_close(connection_);
    }
*/

/*
void populateExploitDB(const std::vector<std::tuple<std::string, std::string, std::string>>& exploitList) {
    dbOpen();
    sqlite3_stmt* stmt;

    for (const auto& exploit : exploitList) {

      //   char *err_msg;
      char a[1024]="";
   sprintf(a,"INSERT OR REPLACE INTO cve_exploited VALUES ('%s', '%s', '%s')",std::get<0>(exploit).c_str(),std::get<1>(exploit).c_str(),std::get<2>(exploit).c_str());
   printf("hello brother\n"); 
      printf("command ----- %s\n",a);
              sqlite3_exec(connection_, a, 0, 0, (const char*)"");
   printf("hello brother1\n"); 
*/
/*

        std::cout << "Inserting data: " << std::get<0>(exploit) << ", " << std::get<1>(exploit) << ", " << std::get<2>(exploit) << std::endl;
        std::string insertExploitQuery = "INSERT OR REPLACE INTO cve_exploited VALUES (?, ?, ?)";
        int rc = sqlite3_prepare_v2(connection_, insertExploitQuery.c_str(), -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            std::cout << "Failed to prepare SQL statement for cve_exploited: " << sqlite3_errmsg(connection_) << std::endl;
            return;
        }

        // Bind values to the prepared statement
        sqlite3_bind_text(stmt, 1, std::get<0>(exploit).c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, std::get<1>(exploit).c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, std::get<2>(exploit).c_str(), -1, SQLITE_STATIC);

        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            std::cout << "Failed to execute SQL statement for cve_exploited: " << sqlite3_errmsg(connection_) << std::endl;
        }
*/
/*
        sqlite3_finalize(stmt);
    }

    sqlite3_close(connection_);
}

*/



   void populateExploitDB(const std::vector<std::tuple<std::string, std::string, std::string>>& exploitList) {
    dbOpen();
    sqlite3_stmt* stmt;

    for (const auto& exploit : exploitList) {
        std::cout << "Inserting data: " << std::get<0>(exploit) << ", " << std::get<1>(exploit) << ", " << std::get<2>(exploit) << std::endl;
        std::string insertExploitQuery = "INSERT OR REPLACE INTO cve_exploited VALUES (?, ?, ?)";
        int rc = sqlite3_prepare_v2(connection_, insertExploitQuery.c_str(), -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            std::cout << "Failed to prepare SQL statement for cve_exploited: " << sqlite3_errmsg(connection_) << std::endl;
            sqlite3_close(connection_);
            return;
        }

        // Bind values to the prepared statement
        rc = sqlite3_bind_text(stmt, 1, std::get<0>(exploit).c_str(), -1, SQLITE_STATIC);
        if (rc != SQLITE_OK) {
            std::cout << "Failed to bind value for column 1: " << sqlite3_errmsg(connection_) << std::endl;
            sqlite3_finalize(stmt);
            sqlite3_close(connection_);
            return;
        }

        rc = sqlite3_bind_text(stmt, 2, std::get<1>(exploit).c_str(), -1, SQLITE_STATIC);
        if (rc != SQLITE_OK) {
            std::cout << "Failed to bind value for column 2: " << sqlite3_errmsg(connection_) << std::endl;
            sqlite3_finalize(stmt);
            sqlite3_close(connection_);
            return;
        }

        rc = sqlite3_bind_text(stmt, 3, std::get<2>(exploit).c_str(), -1, SQLITE_STATIC);
        if (rc != SQLITE_OK) {
            std::cout << "Failed to bind value for column 3: " << sqlite3_errmsg(connection_) << std::endl;
            sqlite3_finalize(stmt);
            sqlite3_close(connection_);
            return;
        }

        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            std::cout << "Failed to execute SQL statement for cve_exploited: " << sqlite3_errmsg(connection_) << std::endl;
        }

        sqlite3_finalize(stmt);
    }

    sqlite3_close(connection_);
}

};

int main() {
    CVEDataProcessor processor;
    processor.refresh();

    return 0;
}

