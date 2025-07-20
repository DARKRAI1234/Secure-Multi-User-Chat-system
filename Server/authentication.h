#ifndef AUTHENTICATION_H
#define AUTHENTICATION_H

#include <memory>
#include <string>
#include <mysql_driver.h>
#include <cppconn/driver.h>
#include <cppconn/connection.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/resultset.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "connectionpool.h"

class Authentication {
private:
    std::shared_ptr<ConnectionPool> connectionPool;
    std::unique_ptr<sql::Connection> createDirectConnection();

public:
    Authentication(std::shared_ptr<ConnectionPool> pool);
    bool registerUser(const std::string& username, const std::string& password, const std::string& email);
    bool loginUser(const std::string& username, const std::string& password);
    bool checkUserExists(const std::string& username);
    std::string hashPassword(const std::string& password, const std::string& salt);
    std::string generateSalt();
    void createUserTable();
};

#endif
