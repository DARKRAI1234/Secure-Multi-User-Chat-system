#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <memory>
#include <sstream>
#include <chrono>
#include <ctime>
#include <iomanip>

// Complete MySQL Connector C++ 9.3 includes
#include <mysql_driver.h>
#include <cppconn/driver.h>
#include <cppconn/connection.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/resultset.h>
#include <cppconn/exception.h>

#include "authentication.h"
#include "group_handler.h"
#include "connectionpool.h"

#pragma comment(lib, "ws2_32.lib")


#pragma comment(lib, "ws2_32.lib")

class ChatServer {
private:
    SOCKET serverSocket;
    std::map<SOCKET, std::string> clients;
    std::mutex clientsMutex;
    std::shared_ptr<ConnectionPool> connectionPool;
    std::unique_ptr<Authentication> auth;
    std::unique_ptr<GroupHandler> groupHandler;

    static constexpr int PORT = 8080;
    static constexpr int BUFFER_SIZE = 1024;

public:
    ChatServer() {
        try {
            std::cout << "=== Initializing Chat Server (Direct Connections) ===" << std::endl;

            initializeWinsock();
            std::cout << "Winsock initialized" << std::endl;

            createServerSocket();
            std::cout << "Server socket created" << std::endl;

            // Create database and tables
            createDatabaseIfNotExists();
            std::cout << "Database verified/created" << std::endl;

            // Skip connection pool - create dummy for compatibility
            connectionPool = nullptr;

            // Initialize modules (they'll use direct connections)
            auth = std::make_unique<Authentication>(connectionPool);
            std::cout << "Authentication module initialized" << std::endl;

            groupHandler = std::make_unique<GroupHandler>(connectionPool);
            std::cout << "Group handler initialized" << std::endl;

            std::cout << "=== Chat Server Ready (Direct Connections) ===" << std::endl;

        }
        catch (const std::exception& e) {
            std::cerr << "Server initialization error: " << e.what() << std::endl;
            throw;
        }
    }

    ~ChatServer() {
        cleanup();
    }

    void createDatabaseIfNotExists() {
        try {
            std::cout << "Creating database with confirmed working connection..." << std::endl;

            sql::mysql::MySQL_Driver* driver = sql::mysql::get_mysql_driver_instance();
            auto conn = std::unique_ptr<sql::Connection>(
                driver->connect("tcp://127.0.0.1:3306", "root", "182005kamalN"));

            std::unique_ptr<sql::Statement> stmt(conn->createStatement());
            stmt->execute("CREATE DATABASE IF NOT EXISTS chat_db");
            stmt->execute("USE chat_db");

            // Complete users table creation
            std::cout << "Creating users table..." << std::endl;
            stmt->execute("CREATE TABLE IF NOT EXISTS users ("
                "id INT AUTO_INCREMENT PRIMARY KEY, "
                "username VARCHAR(50) UNIQUE NOT NULL, "
                "password_hash VARCHAR(64) NOT NULL, "
                "salt VARCHAR(32) NOT NULL, "
                "email VARCHAR(100), "
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            std::cout << "Users table created successfully" << std::endl;

            // Create chat_groups table
            std::cout << "Creating chat_groups table..." << std::endl;
            stmt->execute("CREATE TABLE IF NOT EXISTS chat_groups ("
                "id INT AUTO_INCREMENT PRIMARY KEY, "
                "group_name VARCHAR(100) NOT NULL, "
                "created_by VARCHAR(50) NOT NULL, "
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            std::cout << "Chat_groups table created successfully" << std::endl;

            // Create group_members table
            std::cout << "Creating group_members table..." << std::endl;
            stmt->execute("CREATE TABLE IF NOT EXISTS group_members ("
                "group_id INT, "
                "username VARCHAR(50), "
                "joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
                "PRIMARY KEY (group_id, username), "
                "FOREIGN KEY (group_id) REFERENCES chat_groups(id) ON DELETE CASCADE"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            std::cout << "Group_members table created successfully" << std::endl;
            std::cout << "All database operations completed successfully" << std::endl;

        }
        catch (sql::SQLException& e) {
            std::cerr << "SQL Exception during table creation:" << std::endl;
            std::cerr << "  Error: " << e.what() << std::endl;
            std::cerr << "  Error Code: " << e.getErrorCode() << std::endl;
            std::cerr << "  SQL State: " << e.getSQLState() << std::endl;
            throw;
        }
        catch (std::exception& e) {
            std::cerr << "General exception during database setup: " << e.what() << std::endl;
            throw;
        }
    }

    void initializeWinsock() {
        WSADATA wsaData;
        int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (result != 0) {
            std::cerr << "WSAStartup failed: " << result << std::endl;
            std::exit(1);
        }
    }

    void createServerSocket() {
        serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (serverSocket == INVALID_SOCKET) {
            std::cerr << "Socket creation failed: " << WSAGetLastError() << std::endl;
            WSACleanup();
            std::exit(1);
        }

        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(PORT);

        if (bind(serverSocket, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
            std::cerr << "Bind failed: " << WSAGetLastError() << std::endl;
            closesocket(serverSocket);
            WSACleanup();
            std::exit(1);
        }

        if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
            std::cerr << "Listen failed: " << WSAGetLastError() << std::endl;
            closesocket(serverSocket);
            WSACleanup();
            std::exit(1);
        }
    }

    void run() {
        std::cout << "Chat server running on port " << PORT << std::endl;

        while (true) {
            sockaddr_in clientAddr{};
            int clientAddrLen = sizeof(clientAddr);
            SOCKET clientSocket = accept(serverSocket, reinterpret_cast<sockaddr*>(&clientAddr), &clientAddrLen);

            if (clientSocket == INVALID_SOCKET) {
                std::cerr << "Accept failed: " << WSAGetLastError() << std::endl;
                continue;
            }

            std::cout << "New client connected" << std::endl;
            std::thread clientThread(&ChatServer::handleClient, this, clientSocket);
            clientThread.detach();
        }
    }

    void handleClient(SOCKET clientSocket) {
        try {
            char buffer[BUFFER_SIZE];
            std::string username;
            bool authenticated = false;

            // Authentication phase
            while (!authenticated) {
                ZeroMemory(buffer, BUFFER_SIZE);
                int bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE, 0);

                if (bytesReceived <= 0) {
                    std::cout << "Client disconnected during authentication" << std::endl;
                    closesocket(clientSocket);
                    return;
                }

                std::string command(buffer, bytesReceived);
                std::istringstream iss(command);
                std::string action;
                iss >> action;

                if (action == "LOGIN") {
                    std::string user, pass;
                    iss >> user >> pass;

                    try {
                        if (auth->loginUser(user, pass)) {
                            username = user;
                            authenticated = true;

                            {
                                std::lock_guard<std::mutex> lock(clientsMutex);
                                clients[clientSocket] = username;
                            }

                            std::string response = "LOGIN_SUCCESS";
                            send(clientSocket, response.c_str(), static_cast<int>(response.length()), 0);

                            std::cout << "User " << username << " logged in successfully" << std::endl;
                        }
                        else {
                            std::string response = "LOGIN_FAILED";
                            send(clientSocket, response.c_str(), static_cast<int>(response.length()), 0);
                        }
                    }
                    catch (const std::exception& e) {
                        std::cerr << "Login error for user " << user << ": " << e.what() << std::endl;
                        std::string response = "LOGIN_FAILED";
                        send(clientSocket, response.c_str(), static_cast<int>(response.length()), 0);
                    }
                }
                else if (action == "REGISTER") {
                    std::string user, pass, email;
                    iss >> user >> pass >> email;

                    try {
                        if (auth->registerUser(user, pass, email)) {
                            std::string response = "REGISTER_SUCCESS";
                            send(clientSocket, response.c_str(), static_cast<int>(response.length()), 0);
                            std::cout << "User " << user << " registered successfully" << std::endl;
                        }
                        else {
                            std::string response = "REGISTER_FAILED";
                            send(clientSocket, response.c_str(), static_cast<int>(response.length()), 0);
                        }
                    }
                    catch (const std::exception& e) {
                        std::cerr << "Registration error for user " << user << ": " << e.what() << std::endl;
                        std::string response = "REGISTER_FAILED";
                        send(clientSocket, response.c_str(), static_cast<int>(response.length()), 0);
                    }
                }
            }

            // Main chat loop
            while (true) {
                ZeroMemory(buffer, BUFFER_SIZE);
                int bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE, 0);

                if (bytesReceived <= 0) {
                    std::cout << "Client " << username << " disconnected" << std::endl;
                    break;
                }

                std::string message(buffer, bytesReceived);
                processMessage(clientSocket, username, message);
            }

        }
        catch (const std::exception& e) {
            std::cerr << "Error handling client: " << e.what() << std::endl;
        }

        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            clients.erase(clientSocket);
        }
        closesocket(clientSocket);
    }

    void processMessage(SOCKET clientSocket, const std::string& username, const std::string& message) {
        std::istringstream iss(message);
        std::string command;
        iss >> command;

        try {
            if (command == "MESSAGE") {
                std::string recipient;
                iss >> recipient;
                std::string content;
                std::getline(iss, content);
                if (!content.empty() && content[0] == ' ') {
                    content = content.substr(1);
                }

                sendDirectMessage(username, recipient, content);

            }
            else if (command == "GROUP_MESSAGE") {
                int groupId;
                iss >> groupId;
                std::string content;
                std::getline(iss, content);
                if (!content.empty() && content[0] == ' ') {
                    content = content.substr(1);
                }

                sendGroupMessage(username, groupId, content);

            }
            else if (command == "CREATE_GROUP") {
                std::string groupName;
                iss >> groupName;

                if (groupHandler->createGroup(groupName, username)) {
                    std::string response = "GROUP_CREATED " + groupName;
                    send(clientSocket, response.c_str(), static_cast<int>(response.length()), 0);
                }
                else {
                    std::string response = "GROUP_CREATE_FAILED";
                    send(clientSocket, response.c_str(), static_cast<int>(response.length()), 0);
                }

            }
            else if (command == "JOIN_GROUP") {
                int groupId;
                iss >> groupId;

                if (groupHandler->addMemberToGroup(groupId, username)) {
                    std::string response = "GROUP_JOINED " + std::to_string(groupId);
                    send(clientSocket, response.c_str(), static_cast<int>(response.length()), 0);
                }
                else {
                    std::string response = "GROUP_JOIN_FAILED";
                    send(clientSocket, response.c_str(), static_cast<int>(response.length()), 0);
                }

            }
            else if (command == "LIST_GROUPS") {
                auto allGroups = groupHandler->getAllGroups();
                std::string response = "GROUPS_LIST ";
                for (const auto& group : allGroups) {
                    response += std::to_string(group.groupId) + ":" + group.groupName + ";";
                }
                send(clientSocket, response.c_str(), static_cast<int>(response.length()), 0);
            }
            else if (command == "REFRESH_GROUPS") {
                groupHandler->refreshGroups();
                auto allGroups = groupHandler->getAllGroups();
                std::string response = "GROUPS_LIST ";
                for (const auto& group : allGroups) {
                    response += std::to_string(group.groupId) + ":" + group.groupName + ";";
                }
                send(clientSocket, response.c_str(), static_cast<int>(response.length()), 0);
            }
            else if (command == "MY_GROUPS") {
                auto userGroups = groupHandler->getUserGroups(username);
                std::string response = "MY_GROUPS_LIST ";
                for (const auto& group : userGroups) {
                    response += std::to_string(group.groupId) + ":" + group.groupName + ";";
                }
                send(clientSocket, response.c_str(), static_cast<int>(response.length()), 0);
            }
            else if (command == "LEAVE_GROUP") {
                int groupId;
                iss >> groupId;

                if (groupHandler->removeMemberFromGroup(groupId, username)) {
                    std::string response = "GROUP_LEFT " + std::to_string(groupId);
                    send(clientSocket, response.c_str(), static_cast<int>(response.length()), 0);
                }
                else {
                    std::string response = "GROUP_LEAVE_FAILED";
                    send(clientSocket, response.c_str(), static_cast<int>(response.length()), 0);
                }
            }
            else if (command == "GROUP_INFO") {
                int groupId;
                iss >> groupId;

                if (groupHandler->groupExists(groupId)) {
                    GroupInfo info = groupHandler->getGroupInfo(groupId);
                    std::string response = "GROUP_INFO " + std::to_string(groupId) + ":" +
                        info.groupName + ":" + info.createdBy + ":" +
                        std::to_string(info.members.size());

                    // Add member list
                    response += ":";
                    for (size_t i = 0; i < info.members.size(); ++i) {
                        response += info.members[i];
                        if (i < info.members.size() - 1) {
                            response += ",";
                        }
                    }

                    send(clientSocket, response.c_str(), static_cast<int>(response.length()), 0);
                }
                else {
                    std::string response = "GROUP_NOT_FOUND";
                    send(clientSocket, response.c_str(), static_cast<int>(response.length()), 0);
                }
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Error processing message from " << username << ": " << e.what() << std::endl;
        }
    }

    void sendDirectMessage(const std::string& sender, const std::string& recipient, const std::string& content) {
        std::string timestamp = getCurrentTimestamp();
        std::string formattedMessage = "[" + timestamp + "] " + sender + " -> " + recipient + ": " + content;

        std::lock_guard<std::mutex> lock(clientsMutex);
        for (const auto& pair : clients) {
            if (pair.second == recipient) {
                send(pair.first, formattedMessage.c_str(), static_cast<int>(formattedMessage.length()), 0);
                break;
            }
        }

        std::cout << "Direct message: " << formattedMessage << std::endl;
    }

    void sendGroupMessage(const std::string& sender, int groupId, const std::string& content) {
        try {
            if (!groupHandler->isUserInGroup(groupId, sender)) {
                return;
            }

            auto members = groupHandler->getGroupMembers(groupId);
            std::string timestamp = getCurrentTimestamp();
            std::string formattedMessage = "[" + timestamp + "] Group " + std::to_string(groupId) + " - " + sender + ": " + content;

            std::lock_guard<std::mutex> lock(clientsMutex);
            for (const auto& member : members) {
                if (member != sender) {
                    for (const auto& pair : clients) {
                        if (pair.second == member) {
                            send(pair.first, formattedMessage.c_str(), static_cast<int>(formattedMessage.length()), 0);
                            break;
                        }
                    }
                }
            }

            std::cout << "Group message: " << formattedMessage << std::endl;
        }
        catch (const std::exception& e) {
            std::cerr << "Error sending group message: " << e.what() << std::endl;
        }
    }

    std::string getCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        std::time_t time_t_now = std::chrono::system_clock::to_time_t(now);
        std::tm tm_now;
        localtime_s(&tm_now, &time_t_now);
        std::stringstream ss;
        ss << std::put_time(&tm_now, "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

    void cleanup() {
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            for (const auto& pair : clients) {
                closesocket(pair.first);
            }
            clients.clear();
        }
        closesocket(serverSocket);
        WSACleanup();
    }
};

int main() {
    try {
        ChatServer server;
        server.run();
    }
    catch (const std::exception& e) {
        std::cerr << "Server error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
