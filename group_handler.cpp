#include "group_handler.h"
#include <iostream>
#include <string>
#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <atomic>
#include <unordered_map>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fstream>
#include <sstream>
#include <direct.h>
#include <cerrno>

#ifdef _MSC_VER
#pragma comment(lib, "Ws2_32.lib")
#endif

// ThreadSafeQueue definitions (if needed, though they could stay in the header if templated)
template<typename T>
void ThreadSafeQueue<T>::push(T value) {
    std::lock_guard<std::mutex> lock(mutex);
    queue.push(std::move(value));
    cond.notify_one();
}

template<typename T>
bool ThreadSafeQueue<T>::pop(T& value) {
    std::unique_lock<std::mutex> lock(mutex);
    cond.wait(lock, [this] { return !queue.empty(); });
    value = std::move(queue.front());
    queue.pop();
    return true;
}

template<typename T>
bool ThreadSafeQueue<T>::empty() {
    std::lock_guard<std::mutex> lock(mutex);
    return queue.empty();
}

// MessageThreadPool definitions
MessageThreadPool::MessageThreadPool(size_t numThreads) : running(true) {
    for (size_t i = 0; i < numThreads; ++i) {
        workers.emplace_back(&MessageThreadPool::workerFunction, this);
    }
}

MessageThreadPool::~MessageThreadPool() {
    stop();
}

void MessageThreadPool::enqueueMessage(const GroupMessage& message) {
    messageQueue.push(message);
}

void MessageThreadPool::stop() {
    running = false;
    for (size_t i = 0; i < workers.size(); ++i) {
        messageQueue.push(GroupMessage());
    }
    for (auto& worker : workers) {
        if (worker.joinable()) worker.join();
    }
}

void MessageThreadPool::workerFunction() {
    while (running) {
        GroupMessage message;
        if (messageQueue.pop(message)) {
            processMessage(message);
        }
    }
}

void MessageThreadPool::processMessage(const GroupMessage& message) {
    // Add message validation
    if (message.groupName.empty() || message.recipientSockets.empty()) {
        std::cerr << "Invalid message: empty group or no recipients" << std::endl;
        return;
    }

    std::string formattedMessage = "[Group: " + message.groupName + "] " + message.senderName + ": " + message.content + "\n";
    std::cout << "Processing group message: " << formattedMessage;
    
    for (SOCKET socketFd : message.recipientSockets) {
        if (socketFd != INVALID_SOCKET) {
            int result = send(socketFd, formattedMessage.c_str(), formattedMessage.length(), 0);
            if (result == SOCKET_ERROR) {
                std::cerr << "Failed to send to socket " << socketFd << ": " << WSAGetLastError() << std::endl;
            } else {
                std::cout << "Message sent successfully to socket " << socketFd << std::endl;
            }
        }
    }
}

// SynchronizedGroupManager definitions
SynchronizedGroupManager::SynchronizedGroupManager(const std::string& dbPath) 
    : threadPool(4), groupDbPath("C:\\Users\\123ka\\OneDrive\\Desktop\\OS_mini_project\\build\\" + dbPath) {
    // Ensure the build directory exists
    std::string buildDir = "build";
    if (_mkdir(buildDir.c_str()) == 0 || errno == EEXIST) {
        std::cout << "Directory exists or was created for groups" << std::endl;
        
        // Create groups.db if it doesn't exist
        try {
            std::ifstream fileCheck(groupDbPath);
            if (!fileCheck.good()) {
                std::ofstream createFile(groupDbPath, std::ios::out);
                if (!createFile.is_open()) {
                    std::cerr << "Failed to create groups database at: " << groupDbPath << " Error: " << strerror(errno) << std::endl;
                } else {
                    createFile.close();
                    std::cout << "Created new groups database file at: " << groupDbPath << std::endl;
                }
            } else {
                std::cout << "Using existing groups database at: " << groupDbPath << std::endl;
            }
            fileCheck.close();
        } catch (const std::exception& e) {
            std::cerr << "Exception during file creation: " << e.what() << std::endl;
        }
        
        loadGroups();
    }
}

void SynchronizedGroupManager::loadGroups() {
    std::lock_guard<std::mutex> lock(groupMutex);
    try {
        std::ifstream file(groupDbPath);
        if (!file.is_open()) {
            std::cerr << "Could not open groups database: " << strerror(errno) << std::endl;
            return;
        }

        groups.clear();  // Clear existing groups before loading
        std::string line;
        while (std::getline(file, line)) {
            if (line.empty()) continue;
            
            std::istringstream iss(line);
            std::string groupName;
            if (std::getline(iss, groupName, ':')) {
                std::cout << "Loaded group: " << groupName << std::endl;
                groups[groupName] = std::vector<SOCKET>();
            }
        }
        file.close();
        std::cout << "Successfully loaded " << groups.size() << " groups" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error loading groups: " << e.what() << std::endl;
    }
}

void SynchronizedGroupManager::saveGroups() {
    try {
        std::lock_guard<std::mutex> lock(groupMutex);
        std::cout << "Saving groups to: " << groupDbPath << std::endl;
        
        // Open file with explicit sync options
        std::ofstream file(groupDbPath, std::ios::out | std::ios::trunc);
        if (!file.is_open()) {
            std::cerr << "Failed to open groups database for writing at: " << groupDbPath << std::endl;
            return;
        }

        // Write all groups
        for (const auto& group : groups) {
            file << group.first << ":\n";
            file.flush();  // Force write after each group
            
            if (file.fail()) {
                std::cerr << "Error writing group: " << group.first << std::endl;
                break;
            }
        }
        
        // Ensure everything is written
        file.flush();
        file.close();
        
        if (!file.fail()) {
            std::cout << "Successfully saved " << groups.size() << " groups to " << groupDbPath << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error saving groups: " << e.what() << std::endl;
    }
}

bool SynchronizedGroupManager::createGroup(const std::string& groupName, SOCKET creatorSocket) {
    if (groupName.empty()) {
        std::cerr << "Cannot create group with empty name" << std::endl;
        return false;
    }

    try {
        // First check if group exists with a shared lock
        {
            std::lock_guard<std::mutex> lock(groupMutex);
            if (groups.find(groupName) != groups.end()) {
                std::cerr << "Group already exists: " << groupName << std::endl;
                return false;
            }
        }

        // Now create the group with an exclusive lock
        {
            std::lock_guard<std::mutex> lock(groupMutex);
            groups[groupName] = std::vector<SOCKET>{creatorSocket};
            std::cout << "Created new group: " << groupName << std::endl;
            
            // Save groups immediately
            try {
                std::ofstream file(groupDbPath, std::ios::out | std::ios::app);
                if (!file.is_open()) {
                    std::cerr << "Failed to open groups database for writing at: " << groupDbPath << std::endl;
                    groups.erase(groupName);  // Rollback on failure
                    return false;
                }
                
                file << groupName << ":\n";
                file.flush();  // Force write to disk
                file.close();
                
                if (file.fail()) {
                    std::cerr << "Error writing to groups database" << std::endl;
                    groups.erase(groupName);  // Rollback on failure
                    return false;
                }
                
                std::cout << "Successfully saved group " << groupName << " to database" << std::endl;
            } catch (const std::exception& e) {
                std::cerr << "Error saving group to database: " << e.what() << std::endl;
                groups.erase(groupName);  // Rollback on failure
                return false;
            }
        }

        // Send confirmation after releasing lock
        std::string confirmation = "Successfully created and joined group: " + groupName + "\n";
        send(creatorSocket, confirmation.c_str(), confirmation.length(), 0);
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error creating group: " << e.what() << std::endl;
        return false;
    }
}

bool SynchronizedGroupManager::joinGroup(const std::string& groupName, SOCKET userSocket) {
    std::lock_guard<std::mutex> lock(groupMutex);
    if (groups.find(groupName) == groups.end()) return false;
    auto& members = groups[groupName];
    if (std::find(members.begin(), members.end(), userSocket) != members.end()) return false;
    members.push_back(userSocket);
    return true;
}

bool SynchronizedGroupManager::leaveGroup(const std::string& groupName, SOCKET userSocket) {
    std::lock_guard<std::mutex> lock(groupMutex);
    if (groups.find(groupName) == groups.end()) return false;
    auto& members = groups[groupName];
    auto it = std::find(members.begin(), members.end(), userSocket);
    if (it == members.end()) return false;
    members.erase(it);
    if (members.empty()) {
        groups.erase(groupName);
        saveGroups();  // Save after group deletion
    }
    return true;
}

bool SynchronizedGroupManager::sendGroupMessage(const std::string& groupName, SOCKET senderSocket, const std::string& message) {
    std::unique_lock<std::mutex> lock(groupMutex);
    
    auto groupIt = groups.find(groupName);
    if (groupIt == groups.end()) {
        std::cout << "Group not found: " << groupName << std::endl;
        return false;
    }
    
    const auto& members = groupIt->second;
    if (std::find(members.begin(), members.end(), senderSocket) == members.end()) {
        std::cout << "Sender not in group" << std::endl;
        return false;
    }

    std::vector<SOCKET> recipients;
    for (SOCKET member : members) {
        if (member != senderSocket && member != INVALID_SOCKET) {
            recipients.push_back(member);
        }
    }

    std::string senderName = usernames[senderSocket];
    lock.unlock(); // Release lock before enqueueing message
    
    if (!recipients.empty()) {
        GroupMessage groupMsg{groupName, senderName, message, recipients};
        threadPool.enqueueMessage(groupMsg);
        return true;
    }
    
    return false;
}

void SynchronizedGroupManager::registerUser(SOCKET socketFd, const std::string& username) {
    std::lock_guard<std::mutex> lock(groupMutex);
    usernames[socketFd] = username;
}

void SynchronizedGroupManager::unregisterUser(SOCKET socketFd) {
    std::lock_guard<std::mutex> lock(groupMutex);
    for (auto& group : groups) {
        auto& members = group.second;
        members.erase(std::remove(members.begin(), members.end(), socketFd), members.end());
    }
    for (auto it = groups.begin(); it != groups.end();) {
        if (it->second.empty()) it = groups.erase(it);
        else ++it;
    }
    usernames.erase(socketFd);
}

std::vector<std::string> SynchronizedGroupManager::getGroupsForUser(SOCKET socketFd) {
    std::lock_guard<std::mutex> lock(groupMutex);
    std::vector<std::string> userGroups;
    for (const auto& group : groups) {
        const auto& members = group.second;
        if (std::find(members.begin(), members.end(), socketFd) != members.end()) {
            userGroups.push_back(group.first);
        }
    }
    return userGroups;
}

std::vector<std::string> SynchronizedGroupManager::getAllGroups() {
    std::lock_guard<std::mutex> lock(groupMutex);
    std::vector<std::string> groupNames;
    for (const auto& group : groups) {
        groupNames.push_back(group.first);
    }
    return groupNames;
}

std::vector<std::string> SynchronizedGroupManager::getMembersInGroup(const std::string& groupName) {
    std::lock_guard<std::mutex> lock(groupMutex);
    std::vector<std::string> memberNames;
    if (groups.find(groupName) != groups.end()) {
        const auto& members = groups[groupName];
        for (SOCKET socketFd : members) {
            if (usernames.find(socketFd) != usernames.end()) {
                memberNames.push_back(usernames[socketFd]);
            }
        }
    }
    return memberNames;
}