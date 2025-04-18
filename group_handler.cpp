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
    std::string formattedMessage = "[Group: " + message.groupName + "] " + message.senderName + ": " + message.content + "\n";
    std::cout << "Processing group message: " << formattedMessage;
    std::cout << "Recipients count: " << message.recipientSockets.size() << std::endl;
    
    for (SOCKET socketFd : message.recipientSockets) {
        if (socketFd != INVALID_SOCKET) {
            int result = send(socketFd, formattedMessage.c_str(), formattedMessage.length(), 0);
            if (result == SOCKET_ERROR) {
                std::cerr << "Failed to send to socket " << socketFd << ": " << WSAGetLastError() << std::endl;
            }
        }
    }
}

// SynchronizedGroupManager definitions
SynchronizedGroupManager::SynchronizedGroupManager() : threadPool(4) {}

bool SynchronizedGroupManager::createGroup(const std::string& groupName, SOCKET creatorSocket) {
    std::lock_guard<std::mutex> lock(groupMutex);
    if (groups.find(groupName) != groups.end()) return false;
    groups[groupName] = std::vector<SOCKET>{creatorSocket};
    return true;
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
    if (members.empty()) groups.erase(groupName);
    return true;
}

bool SynchronizedGroupManager::sendGroupMessage(const std::string& groupName, SOCKET senderSocket, const std::string& message) {
    std::lock_guard<std::mutex> lock(groupMutex);
    
    std::cout << "Attempting to send message to group: " << groupName << std::endl;
    
    auto groupIt = groups.find(groupName);
    if (groupIt == groups.end()) {
        std::cout << "Group not found: " << groupName << std::endl;
        return false;
    }
    
    const auto& members = groupIt->second;
    if (std::find(members.begin(), members.end(), senderSocket) == members.end() && senderSocket != 0) {
        std::cout << "Sender not in group" << std::endl;
        return false;
    }

    std::vector<SOCKET> recipients;
    for (SOCKET member : members) {
        if (member != senderSocket && member != INVALID_SOCKET) {
            recipients.push_back(member);
        }
    }

    std::string senderName = usernames.count(senderSocket) ? usernames[senderSocket] : "Server";
    std::cout << "Sending message from " << senderName << " to " << recipients.size() << " recipients" << std::endl;
    
    GroupMessage groupMsg{groupName, senderName, message, recipients};
    threadPool.enqueueMessage(groupMsg);
    return true;
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