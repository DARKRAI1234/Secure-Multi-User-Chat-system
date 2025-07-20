#ifndef CONNECTION_POOL_H
#define CONNECTION_POOL_H

#include <memory>
#include <string>
#include <queue>
#include <mutex>
#include <mysql_driver.h>
#include <cppconn/driver.h>
#include <cppconn/connection.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/resultset.h>
#include <cppconn/exception.h>

class ConnectionPool {
private:
    std::string url;
    std::string username;
    std::string password;
    std::string database;
    std::queue<std::unique_ptr<sql::Connection>> connections;
    std::mutex poolMutex;
    int maxConnections;

    std::unique_ptr<sql::Connection> createConnection();

public:
    ConnectionPool(const std::string& url, const std::string& username,
        const std::string& password, const std::string& database,
        int maxConnections = 5);

    std::unique_ptr<sql::Connection> getConnection();
    void returnConnection(std::unique_ptr<sql::Connection> conn);

    ~ConnectionPool();
};

#endif
