// server.cpp - Server-side implementation
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    #define close(s) closesocket(s)
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <unistd.h>
    #include <arpa/inet.h>
#endif


#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <algorithm>
#include <cstring>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

// Configuration constants
const int PORT = 8888;
const int MAX_CLIENTS = 50;
const int BUFFER_SIZE = 1024;

// Forward declarations
class User;
class Group;
class Server;

// User class to store client information
class User {
private:
    std::string username;
    std::string passwordHash;
    int socketFd;
    bool isLoggedIn;
    std::vector<Group*> groups;
    std::mutex userMutex;

public:
    User(const std::string& username, const std::string& passwordHash) 
        : username(username), passwordHash(passwordHash), socketFd(-1), isLoggedIn(false) {}

    // Getters and setters
    std::string getUsername() const { return username; }
    
    std::string getPasswordHash() const { return passwordHash; }
    
    int getSocketFd() const { 
        std::lock_guard<std::mutex> lock(userMutex);
        return socketFd; 
    }
    
    bool isOnline() const { 
        std::lock_guard<std::mutex> lock(userMutex);
        return isLoggedIn; 
    }
    
    void setSocketFd(int fd) {
        std::lock_guard<std::mutex> lock(userMutex);
        socketFd = fd;
    }
    
    void setLoginStatus(bool status) {
        std::lock_guard<std::mutex> lock(userMutex);
        isLoggedIn = status;
    }
    
    void addGroup(Group* group) {
        std::lock_guard<std::mutex> lock(userMutex);
        if (std::find(groups.begin(), groups.end(), group) == groups.end()) {
            groups.push_back(group);
        }
    }
    
    void removeGroup(Group* group) {
        std::lock_guard<std::mutex> lock(userMutex);
        groups.erase(std::remove(groups.begin(), groups.end(), group), groups.end());
    }
    
    std::vector<Group*> getGroups() {
        std::lock_guard<std::mutex> lock(userMutex);
        return groups;
    }
};

// Group chat class
class Group {
private:
    std::string name;
    std::vector<User*> members;
    std::mutex groupMutex;

public:
    Group(const std::string& name) : name(name) {}
    
    std::string getName() const { return name; }
    
    void addMember(User* user) {
        std::lock_guard<std::mutex> lock(groupMutex);
        if (std::find(members.begin(), members.end(), user) == members.end()) {
            members.push_back(user);
            user->addGroup(this);
        }
    }
    
    void removeMember(User* user) {
        std::lock_guard<std::mutex> lock(groupMutex);
        members.erase(std::remove(members.begin(), members.end(), user), members.end());
        user->removeGroup(this);
    }
    
    std::vector<User*> getMembers() {
        std::lock_guard<std::mutex> lock(groupMutex);
        return members;
    }
};

// Server class to handle client connections and message routing
class Server {
private:
    int serverSocket;
    std::vector<std::thread> clientThreads;
    std::unordered_map<std::string, User*> users;
    std::unordered_map<std::string, Group*> groups;
    std::mutex usersMutex;
    std::mutex groupsMutex;
    bool running;

    // Helper function to hash passwords using SHA-256
    std::string hashPassword(const std::string& password) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, password.c_str(), password.length());
        SHA256_Final(hash, &sha256);
        
        std::string hashedPassword;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            char hex[3];
            sprintf(hex, "%02x", hash[i]);
            hashedPassword += hex;
        }
        return hashedPassword;
    }

    // Parse client commands
    void handleClientMessage(int clientSocket, const std::string& message, User* currentUser) {
        std::string command, params;
        size_t spacePos = message.find(' ');
        
        if (spacePos != std::string::npos) {
            command = message.substr(0, spacePos);
            params = message.substr(spacePos + 1);
        } else {
            command = message;
        }
        
        if (command == "/login") {
            if (currentUser) {
                sendMessage(clientSocket, "You are already logged in");
                return;
            }
            
            size_t delimPos = params.find(':');
            if (delimPos == std::string::npos) {
                sendMessage(clientSocket, "Invalid format. Use: /login username:password");
                return;
            }
            
            std::string username = params.substr(0, delimPos);
            std::string password = params.substr(delimPos + 1);
            handleLogin(clientSocket, username, password);
        }
        else if (command == "/register") {
            if (currentUser) {
                sendMessage(clientSocket, "Please logout before registering a new account");
                return;
            }
            
            size_t delimPos = params.find(':');
            if (delimPos == std::string::npos) {
                sendMessage(clientSocket, "Invalid format. Use: /register username:password");
                return;
            }
            
            std::string username = params.substr(0, delimPos);
            std::string password = params.substr(delimPos + 1);
            handleRegistration(clientSocket, username, password);
        }
        else if (command == "/msg") {
            if (!currentUser) {
                sendMessage(clientSocket, "You must be logged in to send messages");
                return;
            }
            
            size_t delimPos = params.find(' ');
            if (delimPos == std::string::npos) {
                sendMessage(clientSocket, "Invalid format. Use: /msg username message");
                return;
            }
            
            std::string recipient = params.substr(0, delimPos);
            std::string msgContent = params.substr(delimPos + 1);
            handlePrivateMessage(currentUser, recipient, msgContent);
        }
        else if (command == "/broadcast") {
            if (!currentUser) {
                sendMessage(clientSocket, "You must be logged in to broadcast messages");
                return;
            }
            
            handleBroadcast(currentUser, params);
        }
        else if (command == "/create_group") {
            if (!currentUser) {
                sendMessage(clientSocket, "You must be logged in to create groups");
                return;
            }
            
            handleCreateGroup(currentUser, params);
        }
        else if (command == "/join_group") {
            if (!currentUser) {
                sendMessage(clientSocket, "You must be logged in to join groups");
                return;
            }
            
            handleJoinGroup(currentUser, params);
        }
        else if (command == "/leave_group") {
            if (!currentUser) {
                sendMessage(clientSocket, "You must be logged in to leave groups");
                return;
            }
            
            handleLeaveGroup(currentUser, params);
        }
        else if (command == "/group_msg") {
            if (!currentUser) {
                sendMessage(clientSocket, "You must be logged in to send group messages");
                return;
            }
            
            size_t delimPos = params.find(' ');
            if (delimPos == std::string::npos) {
                sendMessage(clientSocket, "Invalid format. Use: /group_msg groupname message");
                return;
            }
            
            std::string groupName = params.substr(0, delimPos);
            std::string msgContent = params.substr(delimPos + 1);
            handleGroupMessage(currentUser, groupName, msgContent);
        }
        else if (command == "/list_users") {
            if (!currentUser) {
                sendMessage(clientSocket, "You must be logged in to list users");
                return;
            }
            
            handleListUsers(currentUser);
        }
        else if (command == "/list_groups") {
            if (!currentUser) {
                sendMessage(clientSocket, "You must be logged in to list groups");
                return;
            }
            
            handleListGroups(currentUser);
        }
        else if (command == "/logout") {
            if (!currentUser) {
                sendMessage(clientSocket, "You are not logged in");
                return;
            }
            
            handleLogout(currentUser);
        }
        else if (command == "/help") {
            handleHelp(clientSocket);
        }
        else {
            sendMessage(clientSocket, "Unknown command. Type /help for available commands");
        }
    }

    // Authentication handlers
    void handleLogin(int clientSocket, const std::string& username, const std::string& password) {
        std::lock_guard<std::mutex> lock(usersMutex);
        
        if (users.find(username) == users.end()) {
            sendMessage(clientSocket, "User not found. Please register first");
            return;
        }
        
        User* user = users[username];
        if (user->isOnline()) {
            sendMessage(clientSocket, "User already logged in on another device");
            return;
        }
        
        if (user->getPasswordHash() == hashPassword(password)) {
            user->setSocketFd(clientSocket);
            user->setLoginStatus(true);
            sendMessage(clientSocket, "Login successful. Welcome, " + username + "!");
        } else {
            sendMessage(clientSocket, "Incorrect password");
        }
    }
    
    void handleRegistration(int clientSocket, const std::string& username, const std::string& password) {
        std::lock_guard<std::mutex> lock(usersMutex);
        
        if (users.find(username) != users.end()) {
            sendMessage(clientSocket, "Username already exists");
            return;
        }
        
        if (username.empty() || password.empty()) {
            sendMessage(clientSocket, "Username and password cannot be empty");
            return;
        }
        
        // Create new user with hashed password
        User* newUser = new User(username, hashPassword(password));
        users[username] = newUser;
        
        sendMessage(clientSocket, "Registration successful. You can now login");
    }
    
    void handleLogout(User* user) {
        user->setLoginStatus(false);
        sendMessage(user->getSocketFd(), "You have been logged out");
    }

    // Messaging handlers
    void handlePrivateMessage(User* sender, const std::string& recipientName, const std::string& message) {
        std::lock_guard<std::mutex> lock(usersMutex);
        
        if (users.find(recipientName) == users.end()) {
            sendMessage(sender->getSocketFd(), "User not found: " + recipientName);
            return;
        }
        
        User* recipient = users[recipientName];
        if (!recipient->isOnline()) {
            sendMessage(sender->getSocketFd(), recipientName + " is offline. Message not delivered");
            return;
        }
        
        std::string formattedMsg = "[PM from " + sender->getUsername() + "]: " + message;
        sendMessage(recipient->getSocketFd(), formattedMsg);
        sendMessage(sender->getSocketFd(), "Message sent to " + recipientName);
    }
    
    void handleBroadcast(User* sender, const std::string& message) {
        std::lock_guard<std::mutex> lock(usersMutex);
        
        std::string formattedMsg = "[Broadcast from " + sender->getUsername() + "]: " + message;
        
        for (auto& pair : users) {
            User* user = pair.second;
            if (user->isOnline() && user != sender) {
                sendMessage(user->getSocketFd(), formattedMsg);
            }
        }
        
        sendMessage(sender->getSocketFd(), "Broadcast message sent to all online users");
    }

    // Group handlers
    void handleCreateGroup(User* creator, const std::string& groupName) {
        std::lock_guard<std::mutex> lockGroups(groupsMutex);
        
        if (groups.find(groupName) != groups.end()) {
            sendMessage(creator->getSocketFd(), "Group already exists: " + groupName);
            return;
        }
        
        Group* newGroup = new Group(groupName);
        groups[groupName] = newGroup;
        newGroup->addMember(creator);
        
        sendMessage(creator->getSocketFd(), "Group created: " + groupName);
    }
    
    void handleJoinGroup(User* user, const std::string& groupName) {
        std::lock_guard<std::mutex> lock(groupsMutex);
        
        if (groups.find(groupName) == groups.end()) {
            sendMessage(user->getSocketFd(), "Group not found: " + groupName);
            return;
        }
        
        Group* group = groups[groupName];
        group->addMember(user);
        
        // Notify all group members
        for (User* member : group->getMembers()) {
            if (member->isOnline() && member != user) {
                sendMessage(member->getSocketFd(), user->getUsername() + " has joined the group: " + groupName);
            }
        }
        
        sendMessage(user->getSocketFd(), "You have joined the group: " + groupName);
    }
    
    void handleLeaveGroup(User* user, const std::string& groupName) {
        std::lock_guard<std::mutex> lock(groupsMutex);
        
        if (groups.find(groupName) == groups.end()) {
            sendMessage(user->getSocketFd(), "Group not found: " + groupName);
            return;
        }
        
        Group* group = groups[groupName];
        
        // Check if user is in the group
        auto members = group->getMembers();
        if (std::find(members.begin(), members.end(), user) == members.end()) {
            sendMessage(user->getSocketFd(), "You are not a member of the group: " + groupName);
            return;
        }
        
        group->removeMember(user);
        
        // Notify remaining members
        for (User* member : group->getMembers()) {
            if (member->isOnline()) {
                sendMessage(member->getSocketFd(), user->getUsername() + " has left the group: " + groupName);
            }
        }
        
        sendMessage(user->getSocketFd(), "You have left the group: " + groupName);
        
        // Remove empty groups
        if (group->getMembers().empty()) {
            groups.erase(groupName);
            delete group;
        }
    }
    
    void handleGroupMessage(User* sender, const std::string& groupName, const std::string& message) {
        std::lock_guard<std::mutex> lock(groupsMutex);
        
        if (groups.find(groupName) == groups.end()) {
            sendMessage(sender->getSocketFd(), "Group not found: " + groupName);
            return;
        }
        
        Group* group = groups[groupName];
        
        // Check if user is in the group
        auto members = group->getMembers();
        if (std::find(members.begin(), members.end(), sender) == members.end()) {
            sendMessage(sender->getSocketFd(), "You are not a member of the group: " + groupName);
            return;
        }
        
        std::string formattedMsg = "[" + groupName + "] " + sender->getUsername() + ": " + message;
        
        // Send message to all group members
        for (User* member : members) {
            if (member->isOnline() && member != sender) {
                sendMessage(member->getSocketFd(), formattedMsg);
            }
        }
        
        sendMessage(sender->getSocketFd(), "Message sent to group: " + groupName);
    }

    // Utility handlers
    void handleListUsers(User* user) {
        std::lock_guard<std::mutex> lock(usersMutex);
        
        std::string userList = "Online users:\n";
        for (auto& pair : users) {
            User* u = pair.second;
            if (u->isOnline()) {
                userList += "- " + u->getUsername() + "\n";
            }
        }
        
        sendMessage(user->getSocketFd(), userList);
    }
    
    void handleListGroups(User* user) {
        std::lock_guard<std::mutex> lock(groupsMutex);
        
        std::string groupList = "Available groups:\n";
        for (auto& pair : groups) {
            groupList += "- " + pair.first + "\n";
        }
        
        sendMessage(user->getSocketFd(), groupList);
    }
    
    void handleHelp(int clientSocket) {
        std::string helpText = "Available commands:\n"
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
                               "/help - Show this help message";
        
        sendMessage(clientSocket, helpText);
    }

    // Communication helpers
    void sendMessage(int socketFd, const std::string& message) {
        std::string msg = message + "\n";
        send(socketFd, msg.c_str(), msg.length(), 0);
    }

public:
    Server() : serverSocket(-1), running(false) {}
    
    ~Server() {
        stop();
        
        // Cleanup
        for (auto& pair : users) {
            delete pair.second;
        }
        
        for (auto& pair : groups) {
            delete pair.second;
        }
    }
    
    bool start() {
        // Create socket
        serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (serverSocket == -1) {
            std::cerr << "Error creating socket" << std::endl;
            return false;
        }
        
        // Set socket options
        int opt = 1;
        if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            std::cerr << "Error setting socket options" << std::endl;
            return false;
        }
        
        // Bind socket
        struct sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(PORT);
        
        if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
            std::cerr << "Error binding socket" << std::endl;
            return false;
        }
        
        // Listen for connections
        if (listen(serverSocket, MAX_CLIENTS) < 0) {
            std::cerr << "Error listening for connections" << std::endl;
            return false;
        }
        
        std::cout << "Server started on port " << PORT << std::endl;
        
        running = true;
        
        // Accept client connections
        acceptClients();
        
        return true;
    }
    
    void stop() {
        running = false;
        
        if (serverSocket != -1) {
            close(serverSocket);
            serverSocket = -1;
        }
        
        for (auto& thread : clientThreads) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        
        clientThreads.clear();
    }
    
    void acceptClients() {
        while (running) {
            struct sockaddr_in clientAddr;
            socklen_t clientAddrLen = sizeof(clientAddr);
            
            int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
            
            if (clientSocket < 0) {
                if (!running) break;
                std::cerr << "Error accepting connection" << std::endl;
                continue;
            }
            
            std::string clientIP = inet_ntoa(clientAddr.sin_addr);
            std::cout << "New connection from " << clientIP << ":" << ntohs(clientAddr.sin_port) << std::endl;
            
            // Create a thread to handle the client
            clientThreads.emplace_back(&Server::handleClient, this, clientSocket);
        }
    }
    
    void handleClient(int clientSocket) {
        char buffer[BUFFER_SIZE];
        User* currentUser = nullptr;
        
        // Send welcome message
        sendMessage(clientSocket, "Welcome to the Secure Chat Server!\nType /help for available commands.");
        
        while (running) {
            memset(buffer, 0, BUFFER_SIZE);
            int bytesRead = recv(clientSocket, buffer, BUFFER_SIZE - 1, 0);
            
            if (bytesRead <= 0) {
                break;
            }
            
            std::string message(buffer);
            message.erase(std::remove(message.begin(), message.end(), '\n'), message.end());
            message.erase(std::remove(message.begin(), message.end(), '\r'), message.end());
            
            // Find the current user (if logged in)
            if (!currentUser) {
                std::lock_guard<std::mutex> lock(usersMutex);
                for (auto& pair : users) {
                    if (pair.second->getSocketFd() == clientSocket && pair.second->isOnline()) {
                        currentUser = pair.second;
                        break;
                    }
                }
            }
            
            // Handle the message
            handleClientMessage(clientSocket, message, currentUser);
        }
        
        // Handle disconnection
        if (currentUser) {
            currentUser->setLoginStatus(false);
            currentUser->setSocketFd(-1);
            std::cout << "User " << currentUser->getUsername() << " disconnected" << std::endl;
        } else {
            std::cout << "Client disconnected" << std::endl;
        }
        
        close(clientSocket);
    }
};

int main() {
    #ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "WSAStartup failed" << std::endl;
            return 1;
        }
    #endif
    
    Server server;
    if (!server.start()) {
        std::cerr << "Failed to start server" << std::endl;
        return 1;
    }
    #ifdef _WIN32
        WSACleanup();
    #endif
    
    return 0;
}