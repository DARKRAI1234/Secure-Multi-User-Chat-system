#include "authentication.h"
#include <direct.h>  
#include <errno.h>   
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

// AuthUser definitions
AuthUser::AuthUser() : socketFd(INVALID_SOCKET), isLoggedIn(false) {}

AuthUser::AuthUser(const std::string& username, const std::string& passwordHash, const std::string& salt)
    : username(username), passwordHash(passwordHash), salt(salt), socketFd(INVALID_SOCKET), isLoggedIn(false) {}

std::string AuthUser::getUsername() const { return username; }
std::string AuthUser::getPasswordHash() const { return passwordHash; }
std::string AuthUser::getSalt() const { return salt; }
SOCKET AuthUser::getSocketFd() const { return socketFd; }
bool AuthUser::isOnline() const { return isLoggedIn; }
void AuthUser::setSocketFd(SOCKET fd) { socketFd = fd; }
void AuthUser::setLoginStatus(bool status) { isLoggedIn = status; }

// AuthenticationManager definitions
AuthenticationManager::AuthenticationManager(const std::string& dbFile) : dbFilePath(dbFile) {
    // Create the build directory if it doesn't exist
    std::string buildDir = "build";
    std::cout << "Creating directory: " << buildDir << std::endl;
    
    // Create directory with full permissions
    if (_mkdir(buildDir.c_str()) == 0 || errno == EEXIST) {
        std::cout << "Directory created or already exists" << std::endl;
        OpenSSL_add_all_algorithms();
        
        // Only create the DB file if it does not exist
        {
            std::ifstream fileCheck(dbFilePath);
            if (!fileCheck.good()) {
                std::ofstream test(dbFilePath);
                if (!test.is_open()) {
                    std::cerr << "Failed to create/open database file: " << strerror(errno) << std::endl;
                    throw std::runtime_error("Failed to create/open database file");
                }
                test.close();
            }
        }
        loadUsers();
    } else {
        std::cerr << "Failed to create directory: " << strerror(errno) << std::endl;
        throw std::runtime_error("Failed to create build directory");
    }
}

AuthenticationManager::~AuthenticationManager() {
    saveUsers();
    EVP_cleanup();
}

std::string AuthenticationManager::generateSalt(size_t length) {
    std::vector<unsigned char> saltBuf(length);
    RAND_bytes(saltBuf.data(), static_cast<int>(length));
    std::stringstream ss;
    for (unsigned char byte : saltBuf) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return ss.str();
}

std::string AuthenticationManager::hashPassword(const std::string& password, const std::string& salt) {
    std::string combined = password + salt;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create EVP context");
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen;
    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) ||
        !EVP_DigestUpdate(ctx, combined.c_str(), combined.length()) ||
        !EVP_DigestFinal_ex(ctx, hash, &hashLen)) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to compute hash");
    }
    EVP_MD_CTX_free(ctx);
    std::stringstream ss;
    for (unsigned int i = 0; i < hashLen; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

void AuthenticationManager::loadUsers() {
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
        if (std::getline(iss, username, ':') && std::getline(iss, passwordHash, ':') && std::getline(iss, salt)) {
            users[username] = AuthUser(username, passwordHash, salt);
        }
    }
    file.close();
}

#include <direct.h> // For _getcwd on Windows

bool AuthenticationManager::saveUsers() {
    std::cout << "Saving users to: " << dbFilePath << std::endl;
    
    std::ofstream file(dbFilePath, std::ios::out | std::ios::trunc);
    if (!file.is_open()) {
        std::cerr << "Failed to open file for writing: " << strerror(errno) << std::endl;
        return false;
    }

    bool success = true;
    for (const auto& pair : users) {
        const AuthUser& user = pair.second;
        file << user.getUsername() << ":" 
             << user.getPasswordHash() << ":" 
             << user.getSalt() << "\n";
             
        if (file.fail()) {
            std::cerr << "Error writing to file" << std::endl;
            success = false;
            break;
        }
    }

    file.close();
    if (file.fail() || !success) {
        std::cerr << "Error during file operations" << std::endl;
        return false;
    }

    std::cout << "Successfully saved users database" << std::endl;
    return true;
}

bool AuthenticationManager::registerUser(const std::string& username, const std::string& password) {
    std::cout << "Starting registration for user: " << username << std::endl;
    
    if (username.empty() || password.empty()) {
        std::cerr << "Registration failed: Empty username or password" << std::endl;
        return false;
    }

    // Use RAII for both locks to prevent deadlocks
    std::lock_guard<std::mutex> userLock(userMutex);
    std::lock_guard<std::mutex> fileLock(dbMutex);  // Use std::lock_guard instead of FileLock

    try {
        if (users.find(username) != users.end()) {
            std::cerr << "Registration failed: Username " << username << " already exists" << std::endl;
            return false;
        }

        std::cout << "Generating salt for user: " << username << std::endl;
        std::string salt = generateSalt(16);
        
        std::cout << "Hashing password for user: " << username << std::endl;
        std::string hashedPassword = hashPassword(password, salt);
        
        std::cout << "Creating user: " << username << std::endl;
        users[username] = AuthUser(username, hashedPassword, salt);
        
        std::cout << "Saving users to database" << std::endl;
        if (!saveUsers()) {
            std::cerr << "Failed to save users to database" << std::endl;
            users.erase(username);
            return false;
        }
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Registration failed with exception: " << e.what() << std::endl;
        return false;
    }
}

bool AuthenticationManager::authenticateUser(const std::string& username, const std::string& password) {
    std::lock_guard<std::mutex> lock(userMutex);
    auto it = users.find(username);
    if (it == users.end()) return false;
    const AuthUser& user = it->second;
    std::string hashedPassword = hashPassword(password, user.getSalt());
    return hashedPassword == user.getPasswordHash();
}

bool AuthenticationManager::loginUser(const std::string& username, const std::string& password, SOCKET socketFd) {
    if (!authenticateUser(username, password)) return false;
    std::lock_guard<std::mutex> lock(userMutex);
    AuthUser& user = users[username];
    if (user.isOnline()) return false;
    user.setSocketFd(socketFd);
    user.setLoginStatus(true);
    return true;
}

bool AuthenticationManager::logoutUser(const std::string& username) {
    std::lock_guard<std::mutex> lock(userMutex);
    auto it = users.find(username);
    if (it == users.end()) return false;
    AuthUser& user = it->second;
    if (!user.isOnline()) return false;
    user.setLoginStatus(false);
    user.setSocketFd(INVALID_SOCKET);
    return true;
}

AuthUser* AuthenticationManager::getUserBySocket(SOCKET socketFd) {
    std::lock_guard<std::mutex> lock(userMutex);
    for (auto& pair : users) {
        AuthUser& user = pair.second;
        if (user.getSocketFd() == socketFd && user.isOnline()) return &user;
    }
    return nullptr;
}

AuthUser* AuthenticationManager::getUserByUsername(const std::string& username) {
    std::lock_guard<std::mutex> lock(userMutex);
    auto it = users.find(username);
    if (it != users.end()) return &(it->second);
    return nullptr;
}

std::vector<std::string> AuthenticationManager::getOnlineUsers() {
    std::lock_guard<std::mutex> lock(userMutex);
    std::vector<std::string> onlineUsers;
    for (const auto& pair : users) {
        const AuthUser& user = pair.second;
        if (user.isOnline()) onlineUsers.push_back(user.getUsername());
    }
    return onlineUsers;
}

void AuthenticationManager::handleDisconnection(SOCKET socketFd) {
    AuthUser* user = getUserBySocket(socketFd);
    if (user) logoutUser(user->getUsername());
}