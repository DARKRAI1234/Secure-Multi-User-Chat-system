// authentication.h - Header file for authentication module
#ifndef AUTHENTICATION_H
#define AUTHENTICATION_H

#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <winsock2.h>  // Windows socket headers

// Forward declarations
class AuthUser;
class AuthenticationManager;

// User class with secure password handling
class AuthUser {
private:
    std::string username;
    std::string passwordHash; // Stores salted hash
    std::string salt;         // Random salt for each user
    SOCKET socketFd;          // Windows uses SOCKET type instead of int
    bool isLoggedIn;

public:
    AuthUser();
    AuthUser(const std::string& username, const std::string& passwordHash, const std::string& salt);
    
    std::string getUsername() const;
    std::string getPasswordHash() const;
    std::string getSalt() const;
    SOCKET getSocketFd() const;
    bool isOnline() const;
    
    void setSocketFd(SOCKET fd);
    void setLoginStatus(bool status);
};

class AuthenticationManager {
private:
    std::unordered_map<std::string, AuthUser> users;
    std::mutex userMutex;
    std::string dbFilePath;
    
    // Private methods
    std::string generateSalt(size_t length = 16);
    std::string hashPassword(const std::string& password, const std::string& salt);
    void loadUsers();
    void saveUsers();
    
public:
    AuthenticationManager(const std::string& dbFile = "users.db");
    ~AuthenticationManager();
    
    bool registerUser(const std::string& username, const std::string& password);
    bool authenticateUser(const std::string& username, const std::string& password);
    bool loginUser(const std::string& username, const std::string& password, SOCKET socketFd);
    bool logoutUser(const std::string& username);
    AuthUser* getUserBySocket(SOCKET socketFd);
    AuthUser* getUserByUsername(const std::string& username);
    std::vector<std::string> getOnlineUsers();
    void handleDisconnection(SOCKET socketFd);
};

#endif