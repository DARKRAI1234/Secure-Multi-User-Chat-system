#include "group_handler.h"
#include <cppconn/prepared_statement.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <iostream>
#include <algorithm>
#include <string>
#include <vector>
#include <sstream>
#include <map>
#include <mutex>

// GroupHandler constructor
GroupHandler::GroupHandler(std::shared_ptr<ConnectionPool> pool)
    : connectionPool(pool) {
    std::cout << "Group handler ready (using direct connections)" << std::endl;
    loadGroups(); // Keep the group loading functionality
}

// Helper method to create direct MySQL connection
std::unique_ptr<sql::Connection> GroupHandler::createDirectConnection() {
    try {
        sql::mysql::MySQL_Driver* driver = sql::mysql::get_mysql_driver_instance();
        auto conn = std::unique_ptr<sql::Connection>(
            driver->connect("tcp://127.0.0.1:3306", "root", "182005kamalN"));
        conn->setSchema("chat_db");
        return conn;
    }
    catch (sql::SQLException& e) {
        std::cerr << "Failed to create direct connection: " << e.what() << std::endl;
        return nullptr;
    }
}

void GroupHandler::createTables() {
    try {
        auto conn = createDirectConnection();
        if (!conn) {
            std::cerr << "Failed to create connection for table creation" << std::endl;
            return;
        }

        std::unique_ptr<sql::Statement> stmt(conn->createStatement());

        stmt->execute("CREATE TABLE IF NOT EXISTS chat_groups ("
            "id INT AUTO_INCREMENT PRIMARY KEY, "
            "group_name VARCHAR(100) NOT NULL, "
            "created_by VARCHAR(50) NOT NULL, "
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");

        stmt->execute("CREATE TABLE IF NOT EXISTS group_members ("
            "group_id INT, "
            "username VARCHAR(50), "
            "joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
            "PRIMARY KEY (group_id, username), "
            "FOREIGN KEY (group_id) REFERENCES chat_groups(id) ON DELETE CASCADE)");

        std::cout << "Group tables created successfully" << std::endl;
    }
    catch (sql::SQLException& e) {
        std::cerr << "Error creating group tables: " << e.what() << std::endl;
    }
}

bool GroupHandler::createGroup(const std::string& groupName, const std::string& createdBy) {
    try {
        std::cout << "Creating group with direct connection..." << std::endl;

        auto conn = createDirectConnection();
        if (!conn) {
            std::cerr << "Failed to create connection for group creation" << std::endl;
            return false;
        }

        std::unique_ptr<sql::PreparedStatement> pstmt(
            conn->prepareStatement("INSERT INTO chat_groups (group_name, created_by) VALUES (?, ?)")
        );
        pstmt->setString(1, groupName);
        pstmt->setString(2, createdBy);
        pstmt->execute();

        // Get the created group ID
        std::unique_ptr<sql::Statement> stmt(conn->createStatement());
        std::unique_ptr<sql::ResultSet> res(stmt->executeQuery("SELECT LAST_INSERT_ID() as id"));

        if (res->next()) {
            int groupId = res->getInt("id");
            std::unique_ptr<sql::PreparedStatement> memberStmt(
                conn->prepareStatement("INSERT INTO group_members (group_id, username) VALUES (?, ?)")
            );
            memberStmt->setInt(1, groupId);
            memberStmt->setString(2, createdBy);
            memberStmt->execute();

            std::cout << "Group '" << groupName << "' created successfully with ID: " << groupId << std::endl;
        }

        loadGroups();
        return true;
    }
    catch (sql::SQLException& e) {
        std::cerr << "Error creating group: " << e.what() << std::endl;
        return false;
    }
}

bool GroupHandler::addMemberToGroup(int groupId, const std::string& username) {
    try {
        std::cout << "Adding member to group with direct connection..." << std::endl;

        auto conn = createDirectConnection();
        if (!conn) {
            std::cerr << "Failed to create connection for adding member" << std::endl;
            return false;
        }

        std::unique_ptr<sql::PreparedStatement> pstmt(
            conn->prepareStatement("INSERT IGNORE INTO group_members (group_id, username) VALUES (?, ?)")
        );
        pstmt->setInt(1, groupId);
        pstmt->setString(2, username);
        pstmt->execute();

        std::cout << "Member '" << username << "' added to group " << groupId << " successfully" << std::endl;
        loadGroups();
        return true;
    }
    catch (sql::SQLException& e) {
        std::cerr << "Error adding member to group: " << e.what() << std::endl;
        return false;
    }
}

bool GroupHandler::removeMemberFromGroup(int groupId, const std::string& username) {
    try {
        std::cout << "Removing member from group with direct connection..." << std::endl;

        auto conn = createDirectConnection();
        if (!conn) {
            std::cerr << "Failed to create connection for removing member" << std::endl;
            return false;
        }

        std::unique_ptr<sql::PreparedStatement> pstmt(
            conn->prepareStatement("DELETE FROM group_members WHERE group_id = ? AND username = ?")
        );
        pstmt->setInt(1, groupId);
        pstmt->setString(2, username);
        pstmt->execute();

        std::cout << "Member '" << username << "' removed from group " << groupId << " successfully" << std::endl;
        loadGroups();
        return true;
    }
    catch (sql::SQLException& e) {
        std::cerr << "Error removing member from group: " << e.what() << std::endl;
        return false;
    }
}

// Updated to return all available groups (for /listgroups and /refreshgroups)
std::vector<GroupInfo> GroupHandler::getAllGroups() {
    std::vector<GroupInfo> allGroups;
    std::lock_guard<std::mutex> lock(groupsMutex);

    for (const auto& groupPair : groups) {
        allGroups.push_back(groupPair.second);
    }
    return allGroups;
}

// Updated to return only groups the user is a member of (for /mygroups)
std::vector<GroupInfo> GroupHandler::getUserGroups(const std::string& username) {
    std::vector<GroupInfo> userGroups;
    std::lock_guard<std::mutex> lock(groupsMutex);

    for (const auto& groupPair : groups) {
        const GroupInfo& groupInfo = groupPair.second;
        if (std::find(groupInfo.members.begin(), groupInfo.members.end(), username) != groupInfo.members.end()) {
            userGroups.push_back(groupInfo);
        }
    }
    return userGroups;
}

// New method to get detailed group information (for /groupinfo)
GroupInfo GroupHandler::getGroupInfo(int groupId) {
    std::lock_guard<std::mutex> lock(groupsMutex);
    auto it = groups.find(groupId);
    if (it != groups.end()) {
        return it->second;
    }
    return GroupInfo{}; // Return empty GroupInfo if not found
}

std::vector<std::string> GroupHandler::getGroupMembers(int groupId) {
    std::lock_guard<std::mutex> lock(groupsMutex);
    auto it = groups.find(groupId);
    if (it != groups.end()) {
        return it->second.members;
    }
    return {};
}

bool GroupHandler::isUserInGroup(int groupId, const std::string& username) {
    std::lock_guard<std::mutex> lock(groupsMutex);
    auto it = groups.find(groupId);
    if (it != groups.end()) {
        const auto& members = it->second.members;
        return std::find(members.begin(), members.end(), username) != members.end();
    }
    return false;
}

// Enhanced method to check if group exists
bool GroupHandler::groupExists(int groupId) {
    std::lock_guard<std::mutex> lock(groupsMutex);
    return groups.find(groupId) != groups.end();
}

// Method to get group name by ID
std::string GroupHandler::getGroupName(int groupId) {
    std::lock_guard<std::mutex> lock(groupsMutex);
    auto it = groups.find(groupId);
    if (it != groups.end()) {
        return it->second.groupName;
    }
    return "";
}

void GroupHandler::loadGroups() {
    try {
        std::cout << "Loading groups with direct connection..." << std::endl;

        auto conn = createDirectConnection();
        if (!conn) {
            std::cerr << "Failed to create connection for loading groups" << std::endl;
            return;
        }

        // First check if there are any groups
        std::unique_ptr<sql::Statement> stmt(conn->createStatement());
        std::unique_ptr<sql::ResultSet> countRes(stmt->executeQuery(
            "SELECT COUNT(*) as group_count FROM chat_groups"));

        int groupCount = 0;
        if (countRes->next()) {
            groupCount = countRes->getInt("group_count");
        }

        std::cout << "Found " << groupCount << " groups in database" << std::endl;

        std::lock_guard<std::mutex> lock(groupsMutex);
        groups.clear();

        if (groupCount == 0) {
            std::cout << "No groups found - starting with empty group list" << std::endl;
            return;
        }

        // Load groups with simplified query
        std::unique_ptr<sql::ResultSet> res(stmt->executeQuery(
            "SELECT id, group_name, created_by FROM chat_groups ORDER BY id"));

        while (res->next()) {
            GroupInfo info;
            info.groupId = res->getInt("id");
            info.groupName = res->getString("group_name");
            info.createdBy = res->getString("created_by");

            // Load members for this group
            loadGroupMembers(info.groupId, info.members, conn.get());

            groups[info.groupId] = info;
        }

        std::cout << "Loaded " << groups.size() << " groups successfully" << std::endl;

    }
    catch (sql::SQLException& e) {
        std::cerr << "SQL error loading groups: " << e.what() << std::endl;
    }
    catch (std::exception& e) {
        std::cerr << "Error loading groups: " << e.what() << std::endl;
    }
}

void GroupHandler::loadGroupMembers(int groupId, std::vector<std::string>& members, sql::Connection* conn) {
    try {
        std::unique_ptr<sql::PreparedStatement> pstmt(
            conn->prepareStatement("SELECT username FROM group_members WHERE group_id = ? ORDER BY joined_at")
        );
        pstmt->setInt(1, groupId);
        std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());

        members.clear();
        while (res->next()) {
            members.push_back(res->getString("username"));
        }
    }
    catch (sql::SQLException& e) {
        std::cerr << "Error loading members for group " << groupId << ": " << e.what() << std::endl;
    }
}

// New method to refresh groups from database (for /refreshgroups command)
void GroupHandler::refreshGroups() {
    std::cout << "Refreshing groups from database..." << std::endl;
    loadGroups();
}

// New method to get member count for a group
int GroupHandler::getGroupMemberCount(int groupId) {
    std::lock_guard<std::mutex> lock(groupsMutex);
    auto it = groups.find(groupId);
    if (it != groups.end()) {
        return static_cast<int>(it->second.members.size());
    }
    return 0;
}
