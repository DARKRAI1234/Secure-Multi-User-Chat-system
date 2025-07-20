#ifndef GROUP_HANDLER_H
#define GROUP_HANDLER_H

#include <memory>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <mysql_driver.h>
#include <cppconn/driver.h>
#include <cppconn/connection.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/resultset.h>
#include "connectionpool.h"

struct GroupInfo {
    int groupId;
    std::string groupName;
    std::string createdBy;
    std::vector<std::string> members;
};

class GroupHandler {
private:
    std::shared_ptr<ConnectionPool> connectionPool;
    std::map<int, GroupInfo> groups;
    std::mutex groupsMutex;

    std::unique_ptr<sql::Connection> createDirectConnection();
    void loadGroupMembers(int groupId, std::vector<std::string>& members, sql::Connection* conn);

public:
    GroupHandler(std::shared_ptr<ConnectionPool> pool);

    void createTables();
    bool createGroup(const std::string& groupName, const std::string& createdBy);
    bool addMemberToGroup(int groupId, const std::string& username);
    bool removeMemberFromGroup(int groupId, const std::string& username);

    std::vector<GroupInfo> getAllGroups();
    std::vector<GroupInfo> getUserGroups(const std::string& username);
    GroupInfo getGroupInfo(int groupId);
    std::vector<std::string> getGroupMembers(int groupId);
    bool isUserInGroup(int groupId, const std::string& username);

    bool groupExists(int groupId);
    std::string getGroupName(int groupId);
    int getGroupMemberCount(int groupId);
    void refreshGroups();

    void loadGroups();
};

#endif
