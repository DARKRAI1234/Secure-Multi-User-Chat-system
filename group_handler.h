// group_handler.h - Header file for group handler module
#ifndef GROUP_HANDLER_H
#define GROUP_HANDLER_H

#include <string>
#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <atomic>
#include <unordered_map>
#include <winsock2.h>  // Windows socket headers

// Message structure for group messages
struct GroupMessage {
    std::string groupName;
    std::string senderName;
    std::string content;
    std::vector<SOCKET> recipientSockets;  // Use SOCKET type for Windows
};

// Thread-safe queue for message processing
template<typename T>
class ThreadSafeQueue {
private:
    std::queue<T> queue;
    std::mutex mutex;
    std::condition_variable cond;
    
public:
    void push(T value);
    bool pop(T& value);
    bool empty();
};

// Thread pool for handling concurrent message delivery
class MessageThreadPool {
private:
    std::vector<std::thread> workers;
    ThreadSafeQueue<GroupMessage> messageQueue;
    std::atomic<bool> running;
    
    void workerFunction();
    void processMessage(const GroupMessage& message);
    
public:
    MessageThreadPool(size_t numThreads = std::thread::hardware_concurrency());
    ~MessageThreadPool();
    
    void enqueueMessage(const GroupMessage& message);
    void stop();
};

// Group management with synchronization
class SynchronizedGroupManager {
private:
    std::unordered_map<std::string, std::vector<SOCKET>> groups;  // Use SOCKET type
    std::unordered_map<SOCKET, std::string> usernames;            // Use SOCKET type
    std::mutex groupMutex;
    MessageThreadPool threadPool;
    std::string groupDbPath;
    void saveGroups();
    void loadGroups();
    
public:
    SynchronizedGroupManager(const std::string& dbPath = "groups.db");
    
    bool createGroup(const std::string& groupName, SOCKET creatorSocket);
    bool joinGroup(const std::string& groupName, SOCKET userSocket);
    bool leaveGroup(const std::string& groupName, SOCKET userSocket);
    bool sendGroupMessage(const std::string& groupName, SOCKET senderSocket, const std::string& message);
    void registerUser(SOCKET socketFd, const std::string& username);
    void unregisterUser(SOCKET socketFd);
    std::vector<std::string> getGroupsForUser(SOCKET socketFd);
    std::vector<std::string> getAllGroups();
    std::vector<std::string> getMembersInGroup(const std::string& groupName);
};

#endif // GROUP_HANDLER_H