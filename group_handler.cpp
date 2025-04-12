// group_handler.cpp - Implementation for handling group messages with thread pooling
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

// Message structure for group messages
struct GroupMessage {
    std::string groupName;
    std::string senderName;
    std::string content;
    std::vector<int> recipientSockets;
};

// Thread-safe queue for message processing
template<typename T>
class ThreadSafeQueue {
private:
    std::queue<T> queue;
    std::mutex mutex;
    std::condition_variable cond;
    
public:
    void push(T value) {
        std::lock_guard<std::mutex> lock(mutex);
        queue.push(std::move(value));
        cond.notify_one();
    }
    
    bool pop(T& value) {
        std::unique_lock<std::mutex> lock(mutex);
        
        // Wait until queue has at least one item or stop flag is set
        cond.wait(lock, [this] { return !queue.empty(); });
        
        value = std::move(queue.front());
        queue.pop();
        return true;
    }
    
    bool empty() {
        std::lock_guard<std::mutex> lock(mutex);
        return queue.empty();
    }
};

// Thread pool for handling concurrent message delivery
class MessageThreadPool {
private:
    std::vector<std::thread> workers;
    ThreadSafeQueue<GroupMessage> messageQueue;
    std::atomic<bool> running;
    
    void workerFunction() {
        while (running) {
            GroupMessage message;
            if (messageQueue.pop(message)) {
                processMessage(message);
            }
        }
    }
    
    void processMessage(const GroupMessage& message) {
        std::string formattedMessage = "[" + message.groupName + "] " + message.senderName + ": " + message.content + "\n";
        
        for (int socketFd : message.recipientSockets) {
            send(socketFd, formattedMessage.c_str(), formattedMessage.length(), 0);
        }
    }
    
public:
    MessageThreadPool(size_t numThreads = std::thread::hardware_concurrency()) : running(true) {
        for (size_t i = 0; i < numThreads; ++i) {
            workers.emplace_back(&MessageThreadPool::workerFunction, this);
        }
    }
    
    ~MessageThreadPool() {
        stop();
    }
    
    void enqueueMessage(const GroupMessage& message) {
        messageQueue.push(message);
    }
    
    void stop() {
        running = false;
        
        // Add dummy messages to unblock waiting threads
        for (size_t i = 0; i < workers.size(); ++i) {
            messageQueue.push(GroupMessage());
        }
        
        // Join all worker threads
        for (auto& worker : workers) {
            if (worker.joinable()) {
                worker.join();
            }
        }
    }
};

// Group management with synchronization
class SynchronizedGroupManager {
private:
    std::unordered_map<std::string, std::vector<int>> groups;  // group name -> user socket fds
    std::unordered_map<int, std::string> usernames;            // socket fd -> username
    std::mutex groupMutex;
    MessageThreadPool threadPool;
    
public:
    SynchronizedGroupManager() : threadPool(4) {} // Create a thread pool with 4 worker threads
    
    bool createGroup(const std::string& groupName, int creatorSocket) {
        std::lock_guard<std::mutex> lock(groupMutex);
        
        if (groups.find(groupName) != groups.end()) {
            return false; // Group already exists
        }
        
        groups[groupName] = std::vector<int>{creatorSocket};
        return true;
    }
    
    bool joinGroup(const std::string& groupName, int userSocket) {
        std::lock_guard<std::mutex> lock(groupMutex);
        
        if (groups.find(groupName) == groups.end()) {
            return false; // Group does not exist
        }
        
        auto& members = groups[groupName];
        
        // Check if user is already in the group
        if (std::find(members.begin(), members.end(), userSocket) != members.end()) {
            return false; // User is already in the group
        }
        
        members.push_back(userSocket);
        return true;
    }
    
    bool leaveGroup(const std::string& groupName, int userSocket) {
        std::lock_guard<std::mutex> lock(groupMutex);
        
        if (groups.find(groupName) == groups.end()) {
            return false; // Group does not exist
        }
        
        auto& members = groups[groupName];
        
        // Find and remove the user
        auto it = std::find(members.begin(), members.end(), userSocket);
        if (it == members.end()) {
            return false; // User is not in the group
        }
        
        members.erase(it);
        
        // Remove empty groups
        if (members.empty()) {
            groups.erase(groupName);
        }
        
        return true;
    }
    
    bool sendGroupMessage(const std::string& groupName, int senderSocket, const std::string& message) {
        std::lock_guard<std::mutex> lock(groupMutex);
        
        if (groups.find(groupName) == groups.end()) {
            return false; // Group does not exist
        }
        
        const auto& members = groups[groupName];
        
        // Check if sender is in the group
        if (std::find(members.begin(), members.end(), senderSocket) == members.end()) {
            return false; // Sender is not in the group
        }
        
        // Create recipient list (excluding sender)
        std::vector<int> recipients;
        for (int member : members) {
            if (member != senderSocket) {
                recipients.push_back(member);
            }
        }
        
        // Get the sender's username
        std::string senderName = "Unknown";
        if (usernames.find(senderSocket) != usernames.end()) {
            senderName = usernames[senderSocket];
        }
        
        // Create and enqueue the message
        GroupMessage groupMsg{groupName, senderName, message, recipients};
        threadPool.enqueueMessage(groupMsg);
        
        return true;
    }
    
    void registerUser(int socketFd, const std::string& username) {
        std::lock_guard<std::mutex> lock(groupMutex);
        usernames[socketFd] = username;
    }
    
    void unregisterUser(int socketFd) {
        std::lock_guard<std::mutex> lock(groupMutex);
        
        // Remove the user from all groups
        for (auto& group : groups) {
            auto& members = group.second;
            members.erase(std::remove(members.begin(), members.end(), socketFd), members.end());
        }
        
        // Remove empty groups
        for (auto it = groups.begin(); it != groups.end();) {
            if (it->second.empty()) {
                it = groups.erase(it);
            } else {
                ++it;
            }
        }
        
        // Remove from usernames map
        usernames.erase(socketFd);
    }
    
    std::vector<std::string> getGroupsForUser(int socketFd) {
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
    
    std::vector<std::string> getAllGroups() {
        std::lock_guard<std::mutex> lock(groupMutex);
        
        std::vector<std::string> groupNames;
        for (const auto& group : groups) {
            groupNames.push_back(group.first);
        }
        
        return groupNames;
    }
    
    std::vector<std::string> getMembersInGroup(const std::string& groupName) {
        std::lock_guard<std::mutex> lock(groupMutex);
        
        std::vector<std::string> memberNames;
        
        if (groups.find(groupName) != groups.end()) {
            const auto& members = groups[groupName];
            for (int socketFd : members) {
                if (usernames.find(socketFd) != usernames.end()) {
                    memberNames.push_back(usernames[socketFd]);
                }
            }
        }
        
        return memberNames;
    }
};