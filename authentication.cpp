// authentication.cpp - Secure user authentication module
#include <mutex>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <thread> 

#include <fstream>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
// User class with secure password handling
class AuthUser {
private:
    std::string username;
    std::string passwordHash; // Stores salted hash
    std::string salt;         // Random salt for each user
    SOCKET socketFd;
    bool isLoggedIn;

public:
    AuthUser() : socketFd(-1), isLoggedIn(false) {}
    
    AuthUser(const std::string& username, const std::string& passwordHash, const std::string& salt)
        : username(username), passwordHash(passwordHash), salt(salt), socketFd(-1), isLoggedIn(false) {}
    
    std::string getUsername() const { return username; }
    std::string getPasswordHash() const { return passwordHash; }
    std::string getSalt() const { return salt; }
    int getSocketFd() const { return socketFd; }
    bool isOnline() const { return isLoggedIn; }
    
    void setSocketFd(int fd) { socketFd = fd; }
    void setLoginStatus(bool status) { isLoggedIn = status; }
};

class AuthenticationManager {
private:
    std::unordered_map<std::string, AuthUser> users;
    std::mutex userMutex;
    std::string dbFilePath;
    
    // Generates random salt
    std::string generateSalt(size_t length = 16) {
        std::vector<unsigned char> saltBuf(length);
        RAND_bytes(saltBuf.data(), static_cast<int>(length));
        
        std::stringstream ss;
        for (unsigned char byte : saltBuf) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return ss.str();
    }
    
    // Hashes password with salt using SHA-256
    std::string hashPassword(const std::string& password, const std::string& salt) {
        // Combine password and salt
        std::string combined = password + salt;
        
        // Create and initialize EVP context
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create EVP context");
        }
        
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hashLen;
        
        // Initialize hashing
        if (!EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) ||
            !EVP_DigestUpdate(ctx, combined.c_str(), combined.length()) ||
            !EVP_DigestFinal_ex(ctx, hash, &hashLen)) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("Failed to compute hash");
        }
        
        EVP_MD_CTX_free(ctx);
        
        // Convert to hex string
        std::stringstream ss;
        for (unsigned int i = 0; i < hashLen; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }
        
        return ss.str();
    }
    
    // Load users from database file
    void loadUsers() {
        std::lock_guard<std::mutex> lock(userMutex);
        std::ifstream file(dbFilePath);
        
        if (!file.is_open()) {
            std::cerr << "Could not open user database file. Creating new database." << std::endl;
            return;
        }
        
        std::string line;
        while (std::getline(file, line)) {
            std::istringstream iss(line);
            std::string username, passwordHash, salt;
            
            if (std::getline(iss, username, ':') && 
                std::getline(iss, passwordHash, ':') && 
                std::getline(iss, salt)) {
                
                users[username] = AuthUser(username, passwordHash, salt);
            }
        }
        
        file.close();
    }
    
    // Save users to database file
    void saveUsers() {
        std::lock_guard<std::mutex> lock(userMutex);
        std::ofstream file(dbFilePath);
        
        if (!file.is_open()) {
            std::cerr << "Error: Could not open user database file for writing" << std::endl;
            return;
        }
        
        for (const auto& pair : users) {
            const AuthUser& user = pair.second;
            file << user.getUsername() << ":" << user.getPasswordHash() << ":" << user.getSalt() << std::endl;
        }
        
        file.close();
    }
    
public:
    AuthenticationManager(const std::string& dbFile = "users.db") : dbFilePath(dbFile) {
        // Initialize OpenSSL
        OpenSSL_add_all_algorithms();
        
        // Load existing users
        loadUsers();
    }
    
    ~AuthenticationManager() {
        // Save users before shutting down
        saveUsers();
        
        // Clean up OpenSSL
        EVP_cleanup();
    }
    
    // Register a new user
    bool registerUser(const std::string& username, const std::string& password) {
        if (username.empty() || password.empty()) {
            return false;
        }
        
        std::lock_guard<std::mutex> lock(userMutex);
        
        // Check if user already exists
        if (users.find(username) != users.end()) {
            return false;
        }
        
        // Generate salt and hash the password
        std::string salt = generateSalt();
        std::string hashedPassword = hashPassword(password, salt);
        
        // Create the user
        users[username] = AuthUser(username, hashedPassword, salt);
        
        // Save to database
        saveUsers();
        
        return true;
    }
    
    // Authenticate a user
    bool authenticateUser(const std::string& username, const std::string& password) {
        std::lock_guard<std::mutex> lock(userMutex);
        
        // Check if user exists
        auto it = users.find(username);
        if (it == users.end()) {
            return false;
        }
        
        const AuthUser& user = it->second;
        
        // Hash the provided password with the user's salt
        std::string hashedPassword = hashPassword(password, user.getSalt());
        
        // Compare with stored hash
        return hashedPassword == user.getPasswordHash();
    }
    
    // Login a user
    bool loginUser(const std::string& username, const std::string& password, SOCKET socketFd) {
        if (!authenticateUser(username, password)) {
            return false;
        }
        
        std::lock_guard<std::mutex> lock(userMutex);
        
        // Check if user is already logged in
        AuthUser& user = users[username];
        if (user.isOnline()) {
            return false;
        }
        
        // Set user's socket and login status
        user.setSocketFd(socketFd);
        user.setLoginStatus(true);
        
        return true;
    }
    
    // Logout a user
    bool logoutUser(const std::string& username) {
        std::lock_guard<std::mutex> lock(userMutex);
        
        auto it = users.find(username);
        if (it == users.end()) {
            return false;
        }
        
        AuthUser& user = it->second;
        if (!user.isOnline()) {
            return false;
        }
        
        user.setLoginStatus(false);
        user.setSocketFd(-1);
        
        return true;
    }
    
    // Get a user by socket file descriptor
    AuthUser* getUserBySocket(SOCKET socketFd) {
        std::lock_guard<std::mutex> lock(userMutex);
        
        for (auto& pair : users) {
            AuthUser& user = pair.second;
            if (user.getSocketFd() == socketFd && user.isOnline()) {
                return &user;
            }
        }
        
        return nullptr;
    }
    
    // Get a user by username
    AuthUser* getUserByUsername(const std::string& username) {
        std::lock_guard<std::mutex> lock(userMutex);
        
        auto it = users.find(username);
        if (it != users.end()) {
            return &(it->second);
        }
        
        return nullptr;
    }
    
    // Get all online users
    std::vector<std::string> getOnlineUsers() {
        std::lock_guard<std::mutex> lock(userMutex);
        
        std::vector<std::string> onlineUsers;
        for (const auto& pair : users) {
            const AuthUser& user = pair.second;
            if (user.isOnline()) {
                onlineUsers.push_back(user.getUsername());
            }
        }
        
        return onlineUsers;
    }
    
    // Handle user disconnection (forced logout)
    void handleDisconnection(SOCKET socketFd) {
        AuthUser* user = getUserBySocket(socketFd);
        if (user) {
            logoutUser(user->getUsername());
        }
    }
};