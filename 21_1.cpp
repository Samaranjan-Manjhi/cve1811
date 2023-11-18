#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <sstream>
#include <ctime>
#include <functional>
#include <cstdio>                  
#include <iomanip>
#include <cstdlib>
#include <filesystem>
#include <chrono>
#include <ctime>
#include <fstream>
#include <regex>
#include <sqlite3.h>
#include <cpr/cpr.h>  
#include <cpr/cprver.h>
#include <curl/curl.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <nlohmann/json.hpp>
#include <cpprest/http_client.h>
#include <cpprest/filestream.h>
//#include "sha256.cpp"

using namespace web;
using namespace web::http;
using namespace web::http::client;
using json = nlohmann::json;

class CVEDataProcessor {
public:
    sqlite3* connect; // Declare a SQLite connection handle
    CVEDataProcessor(const std::string& database_file = "/home/escan/aaaa/cvebintool/tables/database_cve0002.db") :
        database_file(database_file) {}

    void nist_Scrape() {
        cpr::Response response = cpr::Get(cpr::Url(FEED));
        if (response.status_code != 200) {
            std::cerr << "Failed to download file from " << FEED << ": " << response.text << std::endl;
            return;
        }
        std::string responseContent = response.text;
    }

    void cache_Update(const std::string& url, const std::string& sha, size_t chunk_size = 16 * 1024) {
        std::string filename = url.substr(url.find_last_of("/") + 1);
        std::string filepath = cachedir + "/" + filename;
        if (filepath.find(cachedir) != 0) {
            throw std::runtime_error("Attempted to write outside cachedir.");
        }
        if (std::filesystem::exists(filepath)) {
            // Calculate SHA-256 hash of the file
            std::string calculatedHash = calculateSHA256File(filepath);
            if (calculatedHash == sha) {
                std::cout << "Correct SHA for " << filename << std::endl;
                return;
            } else {
                std::remove(filepath.c_str());
                std::cout << "SHA mismatch for " << filename << " (have: " << calculatedHash << ", want: " << sha << ")" << std::endl;
            }
        }
        cpr::Response response = cpr::Get(cpr::Url(url));
        if (response.status_code != 200) {
            std::cerr << "Failed to download file from " << url << ": " << response.status_line << std::endl;
            return;
        }
        std::ofstream file(filepath, std::ios::binary);
        if (file) {
            file << response.text;
            file.close();
            // Calculate SHA of the downloaded file
            std::string calculatedHash = calculateSHA256File(filepath);
            if (calculatedHash == sha) {
                std::cout << "Correct SHA for " << filename << std::endl;
            } else {
                std::cerr << "SHA mismatch for " << filename << " (have: " << calculatedHash << ", want: " << sha << ")" << std::endl;
                std::remove(filepath.c_str());
            }
        } else {
            std::cerr << "Failed to open file for writing: " << filepath << std::endl;
        }
    }

    void refresh() {
        std::filesystem::file_time_type lastWriteTime = std::filesystem::last_write_time(database_file);
        std::filesystem::file_time_type currentTime = std::filesystem::last_write_time(database_file);
        auto duration = std::chrono::duration_cast<std::chrono::hours>(currentTime - lastWriteTime);
        if (duration > std::chrono::hours(24)) {
            init_Database();
            nist_Scrape();
        } else {
            std::cout << "Up To Dated..." << std::endl;
        }
        int startYear = 2002;
        int endYear = getCurrentYear();
        downloadCveData(std::to_string(startYear), endYear);
    }

    void init_Database() {
        if (!std::filesystem::exists(cachedir)) {
            std::filesystem::create_directories(cachedir);
        }
        dbOpen();
        char* errMsg;
        const char* cveDataCreate = R"(
            CREATE TABLE IF NOT EXISTS cve_severity (
                cve_number TEXT PRIMARY KEY,
                severity TEXT,
                description TEXT,
                score INTEGER,
                cvss_version INTEGER
            )
        )";
        const char* versionRangeCreate = R"(
            CREATE TABLE IF NOT EXISTS cve_range (
                cve_number TEXT,
                vendor TEXT,
                product TEXT,
                version TEXT,
                versionStartIncluding TEXT,
                versionStartExcluding TEXT,
                versionEndIncluding TEXT,
                versionEndExcluding TEXT,
                year INTEGER
            )
        )";
        const char* indexRange = "CREATE INDEX IF NOT EXISTS product_index ON cve_range (cve_number, vendor, product)";
        if (sqlite3_exec(connect, cveDataCreate, 0, 0, &errMsg) != SQLITE_OK ||
            sqlite3_exec(connect, versionRangeCreate, 0, 0, &errMsg) != SQLITE_OK ||
            sqlite3_exec(connect, indexRange, 0, 0, &errMsg) != SQLITE_OK) {
            std::cerr << "SQL error: " << errMsg << std::endl;
            sqlite3_free(errMsg);
        }
        dbClose();
    }

    void downloadCveData(const std::string& url, int year) {
        std::string localPath = cachedir + "/nvdcve-1.1-" + std::to_string(year) + ".json.gz";
        if (fileExists(localPath)) {
            std::string sha = calculateSHA(localPath);
            if (sha == getSHA(url)) {
                std::cout << "Correct SHA for " << localPath << std::endl;
                return;
            } else {
                std::remove(localPath.c_str());
                std::cout << "SHA mismatch for " << localPath << std::endl;
            }
        }
        std::cout << "Updating CVE cache for " << localPath << std::endl;
        cpr::Response response = cpr::Get(cpr::Url(url));
        if (response.status_code != 200) {
            std::cerr << "Failed to download file from " << url << ": " << response.status_line << std::endl;
            return;
        }
        std::ofstream file(localPath, std::ios::binary);
        if (file) {
            file << response.text;
            file.close();
            std::string sha = calculateSHA(localPath);
            if (sha == getSHA(url)) {
                std::cout << "Correct SHA for " << localPath << std::endl;
            } else {
                std::cerr << "SHA mismatch for " << localPath << std::endl;
                std::remove(localPath.c_str());
            }
        } else {
            std::cerr << "Failed to open file for writing: " << localPath << std::endl;
        }
    }

    void getMeta(const std::string& metaLink) {
        cpr::Response response = cpr::Get(cpr::Url(metaLink));
        if (response.status_code != 200) {
            std::cerr << "Failed to fetch metadata" << std::endl;
            return;
        }
        std::string responseContent = response.text;
    }
    
    std::string calculateSHA256File(const std::string& filename) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        EVP_MD_CTX* mdctx;
        const EVP_MD* md = EVP_sha256();

        mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, md, NULL);

        FILE* file = fopen(filename.c_str(), "rb");
        if (!file) {
            std::cerr << "Failed to open file for SHA calculation: " << filename << std::endl;
            return "";
        }

        while (true) {
            unsigned char buffer[8192];
            size_t bytesRead = fread(buffer, 1, sizeof(buffer), file);
            if (bytesRead == 0) {
                break;
            }
            EVP_DigestUpdate(mdctx, buffer, bytesRead);
        }
        EVP_DigestFinal_ex(mdctx, hash, NULL);
        EVP_MD_CTX_free(mdctx);

        std::ostringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }

        return ss.str();
    }
	
	std::tuple<std::string, std::string, int, int> extractSeverityInfo(const nlohmann::json& cveItem) {
		std::string severity = cveItem["severity"];
		std::string description = cveItem["description"];
		int score = cveItem["score"];
		int cvssVersion = cveItem["cvssVersion"];
		return std::make_tuple(severity, description, score, cvssVersion);
	}
	
    void insertCveSeverity(const std::string& cveNumber, const std::string& severity, const std::string& description, int score, int cvssVersion) {
    	sqlite3* connect;
		dbOpen();
		const char* insertQuery = R"(
		    INSERT OR REPLACE INTO cve_severity (
		        cve_number,
		        severity,
		        description,
		        score,
		        cvss_version
		    )
		    VALUES (?, ?, ?, ?, ?)
		)";
		char* errMsg;
		if (sqlite3_exec(connect, insertQuery, 0, 0, &errMsg) != SQLITE_OK) {
		    std::cerr << "SQL error: " << errMsg << std::endl;
		    sqlite3_free(errMsg);
		}
		dbClose();
    }

    void insertCveData(const std::string& jsonFile, int year) {
        std::ifstream file(jsonFile);
        nlohmann::json jsonData;
        file >> jsonData;
        file.close();
        
        for (const auto& cveItem : jsonData["CVE_Items"]) {
            std::string cveNumber = cveItem["cve"]["CVE_data_meta"]["ID"];
            auto severityInfo = extractSeverityInfo(cveItem);
            std::string severity = std::get<0>(severityInfo);
            std::string description = std::get<1>(severityInfo);
            int score = std::get<2>(severityInfo);
            int cvssVersion = std::get<3>(severityInfo);

            insertCveSeverity(cveNumber, severity, description, score, cvssVersion);

            if (cveItem.find("configurations") != cveItem.end()) {
                insertCveRangeNode(cveNumber, cveItem["configurations"], year);
            }
        }
    }
    
    std::tuple<std::string, std::string, std::string, std::string, std::string, std::string, std::string, int> extractRangeInfo(const nlohmann::json& node) {
		std::string cveNumber = node["cve"]["CVE_data_meta"]["ID"];
		std::string vendor = "vendor"; 
		std::string product = "product"; 
		std::string versionStartIncluding = "versionStartIncluding"; 
		std::string versionStartExcluding = "versionStartExcluding";
		std::string versionEndIncluding = "versionEndIncluding";
		std::string versionEndExcluding = "versionEndExcluding"; 
		int year = 2002; // Replace with the actual year
		return std::make_tuple(cveNumber, vendor, product, versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding, year);
	}


    void insertCveRangeNode(const std::string& cveNumber, const nlohmann::json& node, int year) {
		dbOpen();
		auto rangeInfo = extractRangeInfo(node);

		const char* insertQuery = R"(
		    INSERT OR REPLACE INTO cve_range (
		        cve_number,
		        vendor,
		        product,
		        versionStartIncluding,
		        versionStartExcluding,
		        versionEndIncluding,
		        versionEndExcluding,
		        year
		    )
		    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		)";

		char* errMsg;
		if (sqlite3_exec(connect, insertQuery, 0, 0, &errMsg) != SQLITE_OK) {
		    std::cerr << "SQL error: " << errMsg << std::endl;
		    sqlite3_free(errMsg);
		}
		dbClose();
	}

    static size_t discardDataCallback(void* /*contents*/, size_t size, size_t nmemb, void* /*userp*/) {
    	//CVEDataProcessor* instance = static_cast<CVEDataProcessor*>(userp);
    	//return instance->handleData(contents, size, nmemb);
    	return size * nmemb;
    }
    
    std::string getSHA(const std::string& url) {
		CURL* curl = curl_easy_init();
		std::string sha256;
		if (curl) {
		    // Set the user data (this instance) to be passed to the callback
		    curl_easy_setopt(curl, CURLOPT_WRITEDATA, this);
		    // Set the write callback function (discardDataCallback)
		    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discardDataCallback);
		    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
		    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L); // Perform a HEAD request
		    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); // Handle redirects
		    CURLcode res = curl_easy_perform(curl);
		    if (res == CURLE_OK) {
		        // The sha256 variable now contains the data received in the response
		        // Calculate the SHA-256 hash of the downloaded content
		        sha256 = calculateSHA256String(sha256);
		    } else {
		        std::cerr << "Failed to perform HEAD request to " << url << ": " << curl_easy_strerror(res) << std::endl;
		    }
		    curl_easy_cleanup(curl);
		}
		return sha256;
	}

    std::string calculateSHA256String(const std::string& input) {
		unsigned char hash[SHA256_DIGEST_LENGTH];
		EVP_MD_CTX* mdctx;
		const EVP_MD* md = EVP_sha256();

		mdctx = EVP_MD_CTX_new();
		EVP_DigestInit_ex(mdctx, md, nullptr);
		EVP_DigestUpdate(mdctx, input.c_str(), input.size());
		EVP_DigestFinal_ex(mdctx, hash, nullptr);
		EVP_MD_CTX_free(mdctx);

		std::ostringstream ss;
		for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
		}

		return ss.str();
	}

private:
    std::string database_file;
    std::string cachedir = "/home/escan/Samar_project/cve_db/cache1/";
    const std::string FEED = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz";
    const std::string META_LINK = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-";
    //const std::regex META_REGEX = std::regex("nvdcve-1.1-[\\d]+.json.gz");
    const std::regex META_REGEX("nvdcve-1.1-\\d+\\.json\\.gz");


    void dbOpen() {
        if (connect == nullptr) {
            int rc = sqlite3_open(database_file.c_str(), &connect);
            if (rc) {
                std::cerr << "Can't open database: " << sqlite3_errmsg(connect) << std::endl;
                exit(1);
            }
        }
    }

    void dbClose() {
        if (connect != nullptr) {
            connect = nullptr;
        }
    }

    bool fileExists(const std::string& filename) {
        return std::filesystem::exists(filename);
    }

    std::string calculateSHA(const std::string& filename) {
    	SHA256_CTX sha256;
		unsigned char hash[SHA256_DIGEST_LENGTH];
		EVP_MD_CTX* mdctx = EVP_MD_CTX_new(); // Declare mdctx here
		const EVP_MD* md = EVP_sha256();
		if (mdctx) {
		    EVP_DigestInit_ex(mdctx, md, nullptr);
		    FILE* file = fopen(filename.c_str(), "rb");
		    if (file) {
		        while (true) {
		            unsigned char buffer[8192];
		            size_t bytesRead = fread(buffer, 1, sizeof(buffer), file);
		            if (bytesRead == 0) {
		                break;
		            }
		            EVP_DigestUpdate(mdctx, buffer, bytesRead);
		        }
		        EVP_DigestFinal_ex(mdctx, hash, nullptr);
		        fclose(file);
		        EVP_MD_CTX_free(mdctx); 
		        std::ostringstream ss;
		        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
		        }
		        return ss.str();
		    } else {
		        std::cerr << "Failed to open file for SHA calculation: " << filename << std::endl;
		    }
		    EVP_MD_CTX_free(mdctx); 
		} else {
		    std::cerr << "Failed to create an EVP_MD_CTX" << std::endl;
		}
		return ""; 
    }

    void downloadFile(const std::string& url, const std::string& localPath) {
    	CURL* curl = curl_easy_init();
        if (curl) {
            FILE* file = fopen(localPath.c_str(), "wb");
            if (file) {
                curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
                curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); // Handle redirects
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, file);

                CURLcode res = curl_easy_perform(curl);

                if (res != CURLE_OK) {
                    std::cerr << "Failed to download file from " << url << ": " << curl_easy_strerror(res) << std::endl;
                    fclose(file);
                    std::remove(localPath.c_str());
                } else {
                    fclose(file);
                }
            } else {
                std::cerr << "Failed to open file for writing: " << localPath << std::endl;
            }

            curl_easy_cleanup(curl);
        }
    }
/*
	void downloadCveData(const std::string& localPath, int year) {
        std::string url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-" + std::to_string(year) + ".json.gz";
        cpr::Response response = cpr::Get(cpr::Url(url));

        if (response.status_code == 200) {
            std::ofstream file(localPath, std::ios::binary);
            if (file) {
                file << response.text;
                file.close();
            } else {
                std::cerr << "Failed to open file for writing: " << localPath << std::endl;
            }
        } else {
            std::cerr << "Failed to download file from " << url << ": " << response.status_line << std::endl;
        }
    }
*/	
	
	void downloadCveData(const std::string& localPath, int year) {
        std::string url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-" + std::to_string(year) + ".json.gz";
        cpr::Response response = cpr::Get(cpr::Url(url));

        if (response.status_code == 200) {
            std::ofstream file(localPath, std::ios::binary);
            if (file) {
                file << response.text;
                file.close();
            } else {
                std::cerr << "Failed to open file for writing: " << localPath << std::endl;
            }
        } else {
            std::cerr << "Failed to download file from " << url << ": " << response.status_line << std::endl;
        }
    }	
	
    int getCurrentYear() {
        std::time_t now = std::time(nullptr);
        std::tm* timeinfo = std::localtime(&now);
        return 1900 + timeinfo->tm_year;
    }
};

int main() {
    CVEDataProcessor cveDataProcessor;
    cveDataProcessor.init_Database();
    int startYear = 2002;
    int endYear = cveDataProcessor.getCurrentYear();
    cveDataProcessor.downloadAndInsertData(startYear, endYear);
    return 0;
}

