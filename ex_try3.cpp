#include <iostream>
#include <sqlite3.h>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <SQLiteCpp/SQLiteCpp.h>

using namespace std;

class CVEDataProcessor {
public:
    CVEDataProcessor(const std::string& database_file = "/home/escan/aaaa/cvebintool/tables/cve_cpp_ex.db")
        : database_(database_file) {
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
    SQLite::Database database_;

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

    void initDatabase() {
        std::cout << "Opening database file: " << database_.getFilename().c_str() << std::endl;

        const char* exploitTableCreate = R"(
            CREATE TABLE IF NOT EXISTS cve_exploited (
                cve_number TEXT,
                product TEXT,
                description TEXT,
                PRIMARY KEY(cve_number)
            )
        )";

        database_.exec(exploitTableCreate);
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
            }

            populateExploitDB(exploitList);
        }
    }

    void populateExploitDB(const std::vector<std::tuple<std::string, std::string, std::string>>& exploitList) {
        SQLite::Transaction transaction(database_);

        for (const auto& exploit : exploitList) {
            try {
                std::cout << "Inserting data: " << std::get<0>(exploit) << ", " << std::get<1>(exploit) << ", " << std::get<2>(exploit) << std::endl;

                // Use a prepared statement to safely bind parameters
                SQLite::Statement query(database_, "INSERT OR REPLACE INTO cve_exploited VALUES (?, ?, ?)");
                query.bind(1, std::get<0>(exploit));
                query.bind(2, std::get<1>(exploit));
                query.bind(3, std::get<2>(exploit));
                query.executeStep();
            } catch (std::exception& e) {
                std::cerr << "SQLite exception: " << e.what() << std::endl;
            }
        }

        transaction.commit();
    }
};

int main() {
    CVEDataProcessor processor;
    processor.refresh();

    return 0;
}

