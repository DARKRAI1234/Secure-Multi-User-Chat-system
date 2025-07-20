#include "connectionpool.h"
#include <cppconn/exception.h>
#include <iostream>

ConnectionPool::ConnectionPool(const std::string& url, const std::string& username,
    const std::string& password, const std::string& database,
    int maxConnections)
    : url(url), username(username), password(password), database(database), maxConnections(maxConnections) {

    std::cout << "Starting connection pool initialization..." << std::endl;
    std::cout << "Initializing connection pool with minimal connections..." << std::endl;

    try {
        // Create one initial connection
        auto conn = createConnection();
        if (conn) {
            connections.push(std::move(conn));
            std::cout << "Successfully created initial connection" << std::endl;
        }

        std::cout << "Connection pool initialized with " << connections.size() << " connection" << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Connection pool initialization error: " << e.what() << std::endl;
        throw;
    }
}

std::unique_ptr<sql::Connection> ConnectionPool::createConnection() {
    try {
        std::cout << "Getting MySQL driver instance..." << std::endl;
        sql::mysql::MySQL_Driver* driver = sql::mysql::get_mysql_driver_instance();

        if (!driver) {
            throw std::runtime_error("Could not get MySQL driver instance");
        }
        std::cout << "Driver obtained successfully. Attempting connection..." << std::endl;

        sql::ConnectOptionsMap connection_properties;
        connection_properties["hostName"] = "127.0.0.1";
        connection_properties["port"] = 3306;
        connection_properties["userName"] = username;
        connection_properties["password"] = password;
        connection_properties["schema"] = database;
        connection_properties["OPT_CONNECT_TIMEOUT"] = 5;
        connection_properties["OPT_READ_TIMEOUT"] = 10;
        connection_properties["OPT_WRITE_TIMEOUT"] = 10;

        std::cout << "Connecting to MySQL at 127.0.0.1:3306..." << std::endl;
        auto conn = std::unique_ptr<sql::Connection>(driver->connect(connection_properties));

        if (!conn) {
            throw std::runtime_error("Failed to create connection");
        }

        std::cout << "Connection established. Setting schema..." << std::endl;
        conn->setSchema(database);
        std::cout << "Schema set successfully. Connection ready." << std::endl;
        std::cout << "Connection created with built-in timeouts" << std::endl;

        return conn;

    }
    catch (sql::SQLException& e) {
        std::cerr << "SQL Exception during connection creation: " << e.what() << std::endl;
        std::cerr << "Error Code: " << e.getErrorCode() << std::endl;
        throw;
    }
    catch (std::exception& e) {
        std::cerr << "General exception during connection creation: " << e.what() << std::endl;
        throw;
    }
}

std::unique_ptr<sql::Connection> ConnectionPool::getConnection() {
    std::unique_lock<std::mutex> lock(poolMutex);

    if (connections.empty()) {
        lock.unlock();
        return createConnection();
    }

    auto conn = std::move(connections.front());
    connections.pop();
    return conn;
}

void ConnectionPool::returnConnection(std::unique_ptr<sql::Connection> conn) {
    if (!conn) return;

    std::lock_guard<std::mutex> lock(poolMutex);
    if (connections.size() < maxConnections) {
        connections.push(std::move(conn));
    }
}

ConnectionPool::~ConnectionPool() {
    std::lock_guard<std::mutex> lock(poolMutex);
    while (!connections.empty()) {
        connections.pop();
    }
}
