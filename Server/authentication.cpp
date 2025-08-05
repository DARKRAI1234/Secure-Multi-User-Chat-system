#include "authentication.h"
#include <cppconn/prepared_statement.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>

Authentication::Authentication(std::shared_ptr<ConnectionPool> pool)
    : connectionPool(pool) {
    std::cout << "Authentication module ready (using direct connections)" << std::endl;
}

std::string Authentication::hashPassword(const std::string& password, const std::string& salt) {
    std::string combined = password + salt;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        throw std::runtime_error("Failed to create EVP_MD_CTX");

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }
    if (1 != EVP_DigestUpdate(mdctx, combined.data(), combined.size())) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }
    if (1 != EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }

    EVP_MD_CTX_free(mdctx);

    std::ostringstream ss;
    for (unsigned int i = 0; i < hash_len; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return ss.str();
}

std::string Authentication::generateSalt() {
    unsigned char salt[16];
    if (RAND_bytes(salt, sizeof(salt)) != 1)
        throw std::runtime_error("RAND_bytes failed");

    std::ostringstream ss;
    for (int i = 0; i < 16; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)salt[i];
    return ss.str();
}

// Helper method to create direct MySQL connection
std::unique_ptr<sql::Connection> Authentication::createDirectConnection() {
    try {
        sql::mysql::MySQL_Driver* driver = sql::mysql::get_mysql_driver_instance();
        auto conn = std::unique_ptr<sql::Connection>(
            driver->connect("tcp://127.0.0.1:3306", "root", "password"));
        conn->setSchema("chat_db");
        return conn;
    }
    catch (sql::SQLException& e) {
        std::cerr << "Failed to create direct connection: " << e.what() << std::endl;
        return nullptr;
    }
}

void Authentication::createUserTable() {
    try {
        std::cout << "Creating users table..." << std::endl;

        auto conn = createDirectConnection();
        if (!conn) {
            throw std::runtime_error("Failed to get connection from pool");
        }

        std::cout << "Connection obtained, creating statement..." << std::endl;
        std::unique_ptr<sql::Statement> stmt(conn->createStatement());
        std::cout << "Statement created successfully" << std::endl;

        std::cout << "Proceeding directly to table creation..." << std::endl;

        std::cout << "Executing CREATE TABLE statement..." << std::endl;
        stmt->execute("CREATE TABLE IF NOT EXISTS users ("
            "id INT AUTO_INCREMENT PRIMARY KEY, "
            "username VARCHAR(50) UNIQUE NOT NULL, "
            "password_hash VARCHAR(64) NOT NULL, "
            "salt VARCHAR(32) NOT NULL, "
            "email VARCHAR(100), "
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        std::cout << "Users table created successfully" << std::endl;

    }
    catch (sql::SQLException& e) {
        std::cerr << "SQL Exception: " << e.what() << std::endl;
        std::cerr << "Error Code: " << e.getErrorCode() << std::endl;
        std::cerr << "SQL State: " << e.getSQLState() << std::endl;

        std::cerr << "Continuing server initialization without user table..." << std::endl;
    }
}

bool Authentication::registerUser(const std::string& username, const std::string& password, const std::string& email) {
    try {
        std::cout << "Registering user with direct connection..." << std::endl;

        if (checkUserExists(username)) {
            std::cout << "User " << username << " already exists" << std::endl;
            return false;
        }

        auto conn = createDirectConnection();
        if (!conn) {
            std::cerr << "Failed to create connection for user registration" << std::endl;
            return false;
        }

        std::string salt = generateSalt();
        std::string hashedPassword = hashPassword(password, salt);

        std::unique_ptr<sql::PreparedStatement> pstmt(
            conn->prepareStatement("INSERT INTO users (username, password_hash, salt, email) VALUES (?, ?, ?, ?)")
        );

        pstmt->setString(1, username);
        pstmt->setString(2, hashedPassword);
        pstmt->setString(3, salt);
        pstmt->setString(4, email);

        pstmt->execute();

        std::cout << "User " << username << " registered successfully" << std::endl;
        return true;

    }
    catch (sql::SQLException& e) {
        std::cerr << "SQL Exception in registerUser():" << std::endl;
        std::cerr << "  Error: " << e.what() << std::endl;
        std::cerr << "  Error Code: " << e.getErrorCode() << std::endl;
        std::cerr << "  SQL State: " << e.getSQLState() << std::endl;
        return false;
    }
    catch (std::exception& e) {
        std::cerr << "General exception in registerUser(): " << e.what() << std::endl;
        return false;
    }
}

bool Authentication::loginUser(const std::string& username, const std::string& password) {
    try {
        std::cout << "Logging in user with direct connection..." << std::endl;

        auto conn = createDirectConnection();
        if (!conn) {
            std::cerr << "Failed to create connection for user login" << std::endl;
            return false;
        }

        std::unique_ptr<sql::PreparedStatement> pstmt(
            conn->prepareStatement("SELECT password_hash, salt FROM users WHERE username = ?")
        );

        pstmt->setString(1, username);
        std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());

        if (res->next()) {
            std::string storedHash = res->getString("password_hash");
            std::string salt = res->getString("salt");
            std::string hashedPassword = hashPassword(password, salt);

            bool loginSuccess = (storedHash == hashedPassword);
            if (loginSuccess) {
                std::cout << "Login successful for user: " << username << std::endl;
            }
            else {
                std::cout << "Login failed for user: " << username << " (incorrect password)" << std::endl;
            }
            return loginSuccess;
        }

        std::cout << "Login failed for user: " << username << " (user not found)" << std::endl;
        return false;

    }
    catch (sql::SQLException& e) {
        std::cerr << "SQL Exception in loginUser():" << std::endl;
        std::cerr << "  Error: " << e.what() << std::endl;
        std::cerr << "  Error Code: " << e.getErrorCode() << std::endl;
        std::cerr << "  SQL State: " << e.getSQLState() << std::endl;
        return false;
    }
    catch (std::exception& e) {
        std::cerr << "General exception in loginUser(): " << e.what() << std::endl;
        return false;
    }
}

bool Authentication::checkUserExists(const std::string& username) {
    try {
        std::cout << "Checking user existence with direct connection..." << std::endl;

        auto conn = createDirectConnection();
        if (!conn) {
            std::cerr << "Failed to create connection for user existence check" << std::endl;
            return false;
        }

        std::unique_ptr<sql::PreparedStatement> pstmt(
            conn->prepareStatement("SELECT COUNT(*) as count FROM users WHERE username = ?")
        );

        pstmt->setString(1, username);
        std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());

        if (res->next()) {
            int count = res->getInt("count");
            std::cout << "User existence check completed: " << (count > 0 ? "exists" : "not found") << std::endl;
            return count > 0;
        }

        return false;

    }
    catch (sql::SQLException& e) {
        std::cerr << "SQL Exception in checkUserExists():" << std::endl;
        std::cerr << "  Error: " << e.what() << std::endl;
        std::cerr << "  Error Code: " << e.getErrorCode() << std::endl;
        std::cerr << "  SQL State: " << e.getSQLState() << std::endl;
        return false;
    }
    catch (std::exception& e) {
        std::cerr << "General exception in checkUserExists(): " << e.what() << std::endl;
        return false;
    }
}

