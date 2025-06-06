// server.cpp - Main server implementation for Windows
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

#include "authentication.h" // Include your authentication header
#include "group_handler.h"  // Include your group handler header

// Constants
const int PORT = 8888;
const int MAX_CLIENTS = 50;
const int BUFFER_SIZE = 4096;

// Global variables
std::atomic<bool> serverRunning(true);
SynchronizedGroupManager groupManager;
// Update the DB_PATH constant
const std::string DB_PATH = "C:\\Users\\123ka\\OneDrive\\Desktop\\OS_mini_project\\build\\users.db";
AuthenticationManager authManager(DB_PATH);

// Function prototypes
void handleClient(SOCKET clientSocket);
void broadcastMessage(const std::string& sender, const std::string& message);
void sendPrivateMessage(const std::string& sender, const std::string& recipient, const std::string& message);
void processCommand(SOCKET clientSocket, const std::string& command);

int main() {
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed" << std::endl;
        return 1;
    }

    // Get local IP address
    char hostName[256];
    if (gethostname(hostName, sizeof(hostName)) == 0) {
        struct addrinfo *result = nullptr;
        struct addrinfo hints = {};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(hostName, nullptr, &hints, &result) == 0) {
            for (struct addrinfo *ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
                struct sockaddr_in *addr = (struct sockaddr_in *)ptr->ai_addr;
                char ipStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &addr->sin_addr, ipStr, sizeof(ipStr));
                std::cout << "Server IP address: " << ipStr << std::endl;
            }
            freeaddrinfo(result);
        }
    }

    // Create socket
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Error creating socket: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    // Set up server address
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);

    // Bind
    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed: " << WSAGetLastError() << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    // Listen
    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed: " << WSAGetLastError() << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "Server started. Listening on port " << PORT << "..." << std::endl;

    // Vector to keep track of client threads
    std::vector<std::thread> clientThreads;

    // Accept connections
    while (serverRunning) {
        // Accept a client connection
        sockaddr_in clientAddr;
        int clientAddrLen = sizeof(clientAddr);
        SOCKET clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
        
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Accept failed: " << WSAGetLastError() << std::endl;
            continue;
        }

        // Get client IP
        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddr.sin_addr), clientIP, INET_ADDRSTRLEN);
        std::cout << "New connection from " << clientIP << std::endl;

        // Create a thread for this client
        clientThreads.push_back(std::thread(handleClient, clientSocket));
    }

    // Wait for all client threads to finish
    for (auto& thread : clientThreads) {
        if (thread.joinable()) {
            thread.join();
        }
    }

    // Close server socket
    closesocket(serverSocket);
    
    // Cleanup Winsock
    WSACleanup();
    
    return 0;
}

void handleClient(SOCKET clientSocket) {
    char buffer[BUFFER_SIZE];
    std::string username;
    bool authenticated = false;

    // Send welcome message
    std::string welcomeMsg = "Welcome to the chat server!\nUse /register username:password to create an account\nUse /login username:password to log in\n";
    send(clientSocket, welcomeMsg.c_str(), welcomeMsg.length(), 0);

    while (serverRunning) {
        // Clear buffer
        memset(buffer, 0, BUFFER_SIZE);
        
        // Receive message
        int bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE - 1, 0);
        
        if (bytesReceived <= 0) {
            // Client disconnected or error
            if (bytesReceived == 0) {
                std::cout << "Client disconnected" << std::endl;
            } else {
                std::cerr << "recv failed: " << WSAGetLastError() << std::endl;
            }
            
            // Handle user logout if they were authenticated
            if (authenticated) {
                authManager.handleDisconnection(clientSocket);
                std::string logoutMsg = username + " has left the chat";
                broadcastMessage("Server", logoutMsg);
            }
            
            break;
        }
        
        // Process message
        std::string message(buffer);
        
        // Check if it's a command
        if (message[0] == '/') {
            processCommand(clientSocket, message);
        } else if (authenticated) {
            // Regular message, broadcast to all
            broadcastMessage(username, message);
        } else {
            // Not authenticated
            std::string errorMsg = "You must log in first. Use /login username:password\n";
            send(clientSocket, errorMsg.c_str(), errorMsg.length(), 0);
        }
    }

    // Close client socket
    closesocket(clientSocket);
}

void processCommand(SOCKET clientSocket, const std::string& command) {
    // Trim any newlines or carriage returns
    std::string trimmedCommand = command;
    size_t end = trimmedCommand.find_last_not_of("\r\n");
    if (end != std::string::npos)
        trimmedCommand = trimmedCommand.substr(0, end + 1);

    // Log received command
    std::cout << "Received command: '" << trimmedCommand << "'" << std::endl;

    // Split command and args
    std::string cmd;
    std::string args;
    size_t spacePos = trimmedCommand.find(' ');
    if (spacePos != std::string::npos) {
        cmd = trimmedCommand.substr(0, spacePos);
        args = trimmedCommand.substr(spacePos + 1);
    } else {
        cmd = trimmedCommand;
        args = "";
    }

    if (cmd == "/register") {
        size_t colonPos = args.find(':');
        if (colonPos != std::string::npos) {
            std::string username = args.substr(0, colonPos);
            std::string password = args.substr(colonPos + 1);

            // Trim whitespace from username and password
            auto ltrim = [](std::string& s) { s.erase(0, s.find_first_not_of(" \t\r\n")); };
            auto rtrim = [](std::string& s) { s.erase(s.find_last_not_of(" \t\r\n") + 1); };
            ltrim(username); rtrim(username);
            ltrim(password); rtrim(password);

            std::string ack = "Processing registration request...\n";
            send(clientSocket, ack.c_str(), ack.length(), 0);
            
            bool success = authManager.registerUser(username, password);
            
            std::string response;
            if (success) {
                response = "Registration successful! You can now login using: /login " + username + ":" + password + "\n";
            } else {
                response = "Registration failed. Username may already exist.\n";
            }
            
            send(clientSocket, response.c_str(), response.length(), 0);
        } else {
            std::string response = "Invalid format. Use /register username:password\n";
            send(clientSocket, response.c_str(), response.length(), 0);
        }
    } else if (cmd == "/login") {
        size_t colonPos = args.find(':');
        if (colonPos != std::string::npos) {
            std::string username = args.substr(0, colonPos);
            std::string password = args.substr(colonPos + 1);

            // Trim whitespace from username and password
            auto ltrim = [](std::string& s) { s.erase(0, s.find_first_not_of(" \t\r\n")); };
            auto rtrim = [](std::string& s) { s.erase(s.find_last_not_of(" \t\r\n") + 1); };
            ltrim(username); rtrim(username);
            ltrim(password); rtrim(password);

            if (authManager.loginUser(username, password, clientSocket)) {
                std::string response = "Login successful. Welcome, " + username + "!\n";
                send(clientSocket, response.c_str(), response.length(), 0);
                std::string joinMsg = username + " has joined the chat";
                broadcastMessage("Server", joinMsg);
                groupManager.registerUser(clientSocket, username);
            } else {
                std::string response = "Login failed. Check your credentials or the user may already be logged in.\n";
                send(clientSocket, response.c_str(), response.length(), 0);
            }
        } else {
            std::string response = "Invalid format. Use /login username:password\n";
            send(clientSocket, response.c_str(), response.length(), 0);
        }
    } else if (cmd == "/logout") {
        // Logout
        AuthUser* user = authManager.getUserBySocket(clientSocket);
        if (user) {
            std::string username = user->getUsername();
            authManager.logoutUser(username);
            
            std::string response = "You have been logged out.\n";
            send(clientSocket, response.c_str(), response.length(), 0);
            
            // Broadcast user left message
            std::string leftMsg = username + " has left the chat";
            broadcastMessage("Server", leftMsg);
        } else {
            std::string response = "You are not logged in.\n";
            send(clientSocket, response.c_str(), response.length(), 0);
        }
    } else if (cmd == "/msg") {
        // Private message
        AuthUser* sender = authManager.getUserBySocket(clientSocket);
        if (!sender) {
            std::string response = "You must log in first.\n";
            send(clientSocket, response.c_str(), response.length(), 0);
            return;
        }
        
        size_t spacePos = args.find(' ');
        if (spacePos != std::string::npos) {
            std::string recipient = args.substr(0, spacePos);
            std::string message = args.substr(spacePos + 1);
            
            sendPrivateMessage(sender->getUsername(), recipient, message);
        } else {
            std::string response = "Invalid format. Use /msg username message\n";
            send(clientSocket, response.c_str(), response.length(), 0);
        }
    } else if (cmd == "/create_group") {
        // Create a group
        AuthUser* user = authManager.getUserBySocket(clientSocket);
        if (!user) {
            std::string response = "You must log in first.\n";
            send(clientSocket, response.c_str(), response.length(), 0);
            return;
        }
        
        if (groupManager.createGroup(args, clientSocket)) {
            std::string response = "Group '" + args + "' created successfully.\n";
            send(clientSocket, response.c_str(), response.length(), 0);
        } else {
            std::string response = "Failed to create group. It may already exist.\n";
            send(clientSocket, response.c_str(), response.length(), 0);
        }
    } else if (cmd == "/join_group") {
        AuthUser* user = authManager.getUserBySocket(clientSocket);
        if (!user) {
            std::string response = "You must log in first.\n";
            send(clientSocket, response.c_str(), response.length(), 0);
            return;
        }
        
        std::cout << "User " << user->getUsername() << " attempting to join group '" << args << "'" << std::endl;
        
        if (groupManager.joinGroup(args, clientSocket)) {
            std::string joinMsg = user->getUsername() + " has joined the group '" + args + "'";
            std::string response = "You have joined group '" + args + "'.\n";
            send(clientSocket, response.c_str(), response.length(), 0);
            
            // Notify other group members
            groupManager.sendGroupMessage(args, clientSocket, "*** " + joinMsg + " ***");
        } else {
            std::string response = "Failed to join group. It may not exist.\n";
            send(clientSocket, response.c_str(), response.length(), 0);
        }
    } else if (cmd == "/leave_group") {
        // Leave a group
        AuthUser* user = authManager.getUserBySocket(clientSocket);
        if (!user) {
            std::string response = "You must log in first.\n";
            send(clientSocket, response.c_str(), response.length(), 0);
            return;
        }
        
        if (groupManager.leaveGroup(args, clientSocket)) {
            std::string response = "You have left group '" + args + "'.\n";
            send(clientSocket, response.c_str(), response.length(), 0);
        } else {
            std::string response = "Failed to leave group. You may not be a member or it doesn't exist.\n";
            send(clientSocket, response.c_str(), response.length(), 0);
        }
    } else if (cmd == "/group_msg") {
        AuthUser* user = authManager.getUserBySocket(clientSocket);
        if (!user) {
            std::string response = "You must log in first.\n";
            send(clientSocket, response.c_str(), response.length(), 0);
            return;
        }
        
        size_t spacePos = args.find(' ');
        if (spacePos != std::string::npos) {
            std::string groupName = args.substr(0, spacePos);
            std::string message = args.substr(spacePos + 1);
            
            std::cout << "Attempting to send group message to '" << groupName << "'" << std::endl;
            std::cout << "From user: " << user->getUsername() << std::endl;
            
            if (groupManager.sendGroupMessage(groupName, clientSocket, message)) {
                std::string confirmation = "Message sent to group '" + groupName + "'\n";
                send(clientSocket, confirmation.c_str(), confirmation.length(), 0);
            } else {
                std::string response = "Failed to send message. You may not be a member of the group or it doesn't exist.\n";
                send(clientSocket, response.c_str(), response.length(), 0);
            }
        } else {
            std::string response = "Invalid format. Use /group_msg groupname message\n";
            send(clientSocket, response.c_str(), response.length(), 0);
        }
    } else if (cmd == "/list_users") {
        // List online users
        std::vector<std::string> onlineUsers = authManager.getOnlineUsers();
        
        std::string response = "Online users (" + std::to_string(onlineUsers.size()) + "):\n";
        for (const auto& user : onlineUsers) {
            response += "- " + user + "\n";
        }
        
        send(clientSocket, response.c_str(), response.length(), 0);
    } else if (cmd == "/list_groups") {
        // List available groups
        std::vector<std::string> groups = groupManager.getAllGroups();
        
        std::string response = "Available groups (" + std::to_string(groups.size()) + "):\n";
        for (const auto& group : groups) {
            response += "- " + group + "\n";
        }
        
        send(clientSocket, response.c_str(), response.length(), 0);
    } else if (cmd == "/help") {
        // Display help
        std::string help = "Available commands:\n"
                          "/register username:password - Create a new account\n"
                          "/login username:password - Log in to your account\n"
                          "/logout - Log out from your account\n"
                          "/msg username message - Send a private message\n"
                          "/broadcast message - Send a message to all online users\n"
                          "/create_group groupname - Create a new group\n"
                          "/join_group groupname - Join an existing group\n"
                          "/leave_group groupname - Leave a group\n"
                          "/group_msg groupname message - Send a message to a group\n"
                          "/list_users - Show online users\n"
                          "/list_groups - Show available groups\n"
                          "/help - Show this help message\n"
                          "/quit - Exit the client\n";
        
        send(clientSocket, help.c_str(), help.length(), 0);
    } else {
        // Unknown command
        std::string response = "Unknown command. Type /help for available commands.\n";
        send(clientSocket, response.c_str(), response.length(), 0);
    }
}

void broadcastMessage(const std::string& sender, const std::string& message) {
    std::string formattedMsg = sender + ": " + message + "\n";
    
    // Get all online users
    std::vector<std::string> onlineUsers = authManager.getOnlineUsers();
    
    for (const auto& username : onlineUsers) {
        AuthUser* user = authManager.getUserByUsername(username);
        if (user && user->isOnline()) {
            SOCKET userSocket = user->getSocketFd();
            send(userSocket, formattedMsg.c_str(), formattedMsg.length(), 0);
        }
    }
}

void sendPrivateMessage(const std::string& sender, const std::string& recipient, const std::string& message) {
    AuthUser* recipientUser = authManager.getUserByUsername(recipient);
    AuthUser* senderUser = authManager.getUserByUsername(sender);
    
    if (!recipientUser || !recipientUser->isOnline()) {
        // Recipient not found or not online
        std::string errorMsg = "User '" + recipient + "' is not online or doesn't exist.\n";
        send(senderUser->getSocketFd(), errorMsg.c_str(), errorMsg.length(), 0);
        return;
    }
    
    // Send to recipient
    std::string msgToRecipient = "[PM from " + sender + "]: " + message + "\n";
    send(recipientUser->getSocketFd(), msgToRecipient.c_str(), msgToRecipient.length(), 0);
    
    // Confirmation to sender
    std::string confirmation = "[PM to " + recipient + "]: " + message + "\n";
    send(senderUser->getSocketFd(), confirmation.c_str(), confirmation.length(), 0);
}