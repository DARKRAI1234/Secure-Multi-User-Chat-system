#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sstream>

#pragma comment(lib, "ws2_32.lib")

class ChatClient {
private:
    SOCKET clientSocket;
    std::string username;
    std::mutex consoleMutex;
    bool connected;

    static const int PORT = 8080;
    static const int BUFFER_SIZE = 1024;

public:
    ChatClient() : connected(false) {
        initializeWinsock();
    }

    ~ChatClient() {
        cleanup();
    }

    void initializeWinsock() {
        WSADATA wsaData;
        int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (result != 0) {
            std::cerr << "WSAStartup failed: " << result << std::endl;
            exit(1);
        }
    }

    bool connectToServer() {
        clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Socket creation failed: " << WSAGetLastError() << std::endl;
            return false;
        }

        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(PORT);

        if (inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr) <= 0) {
            std::cerr << "Invalid address" << std::endl;
            return false;
        }

        if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            std::cerr << "Connection failed: " << WSAGetLastError() << std::endl;
            return false;
        }

        connected = true;
        return true;
    }

    bool authenticate() {
        std::string choice;
        std::cout << "Choose an option:\n1. Login\n2. Register\nEnter choice (1 or 2): ";
        std::cin >> choice;
        std::cin.ignore(); // Clear the input buffer

        if (choice == "1") {
            return login();
        }
        else if (choice == "2") {
            return registerUser();
        }
        else {
            std::cout << "Invalid choice!" << std::endl;
            return false;
        }
    }

    bool login() {
        std::string password;
        std::cout << "Enter username: ";
        std::getline(std::cin, username);
        std::cout << "Enter password: ";
        std::getline(std::cin, password);

        std::string loginCommand = "LOGIN " + username + " " + password;
        send(clientSocket, loginCommand.c_str(), static_cast<int>(loginCommand.length()), 0);

        char buffer[BUFFER_SIZE];
        ZeroMemory(buffer, BUFFER_SIZE);
        int bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE, 0);

        if (bytesReceived > 0) {
            std::string response(buffer, bytesReceived);
            if (response == "LOGIN_SUCCESS") {
                std::cout << "Login successful!" << std::endl;
                return true;
            }
            else {
                std::cout << "Login failed. Invalid credentials." << std::endl;
                return false;
            }
        }

        return false;
    }

    bool registerUser() {
        std::string password, email;
        std::cout << "Enter username: ";
        std::getline(std::cin, username);
        std::cout << "Enter password: ";
        std::getline(std::cin, password);
        std::cout << "Enter email: ";
        std::getline(std::cin, email);

        std::string registerCommand = "REGISTER " + username + " " + password + " " + email;
        send(clientSocket, registerCommand.c_str(), static_cast<int>(registerCommand.length()), 0);

        char buffer[BUFFER_SIZE];
        ZeroMemory(buffer, BUFFER_SIZE);
        int bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE, 0);

        if (bytesReceived > 0) {
            std::string response(buffer, bytesReceived);
            if (response == "REGISTER_SUCCESS") {
                std::cout << "Registration successful! Please login." << std::endl;
                return login(); // Automatically proceed to login
            }
            else {
                std::cout << "Registration failed. Username might already exist." << std::endl;
                return false;
            }
        }

        return false;
    }

    void run() {
        if (!connectToServer()) {
            std::cout << "Failed to connect to server!" << std::endl;
            return;
        }

        std::cout << "Connected to chat server!" << std::endl;

        if (!authenticate()) {
            std::cout << "Authentication failed!" << std::endl;
            return;
        }

        // Start receiving messages in a separate thread
        std::thread receiveThread(&ChatClient::receiveMessages, this);

        showHelp();

        // Main input loop
        std::string input;
        while (connected && std::getline(std::cin, input)) {
            if (input.empty()) continue;

            if (input == "/quit" || input == "/exit") {
                connected = false;
                break;
            }
            else if (input == "/help") {
                showHelp();
            }
            else if (input == "/commands") {
                showAllCommands();
            }
            else if (input.substr(0, 3) == "/dm") {
                handleDirectMessage(input);
            }
            else if (input.substr(0, 6) == "/group") {
                handleGroupMessage(input);
            }
            else if (input.substr(0, 12) == "/creategroup") {
                handleCreateGroup(input);
            }
            else if (input.substr(0, 10) == "/joingroup") {
                handleJoinGroup(input);
            }
            else if (input == "/listgroups") {
                handleListGroups();
            }
            else if (input == "/refreshgroups") {
                handleRefreshGroups();
            }
            else if (input.substr(0, 11) == "/leavegroup") {
                handleLeaveGroup(input);
            }
            else if (input.substr(0, 10) == "/groupinfo") {
                handleGroupInfo(input);
            }
            else if (input == "/mygroups") {
                handleMyGroups();
            }
            else if (input == "/status") {
                handleStatus();
            }
            else if (input == "/clear") {
                clearScreen();
            }
            else {
                std::cout << "Unknown command. Type /help or /commands for available commands." << std::endl;
            }
        }

        if (receiveThread.joinable()) {
            receiveThread.join();
        }
    }

    void receiveMessages() {
        char buffer[BUFFER_SIZE];

        while (connected) {
            ZeroMemory(buffer, BUFFER_SIZE);
            int bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE, 0);

            if (bytesReceived <= 0) {
                std::lock_guard<std::mutex> lock(consoleMutex);
                std::cout << "Connection lost!" << std::endl;
                connected = false;
                break;
            }

            std::string message(buffer, bytesReceived);

            {
                std::lock_guard<std::mutex> lock(consoleMutex);
                std::cout << message << std::endl;
            }
        }
    }

    void handleDirectMessage(const std::string& input) {
        std::istringstream iss(input);
        std::string command, recipient, content;
        iss >> command >> recipient;
        std::getline(iss, content);

        if (recipient.empty() || content.empty()) {
            std::cout << "Usage: /dm <recipient> <message>" << std::endl;
            return;
        }

        // Remove leading space from content
        if (!content.empty() && content[0] == ' ') {
            content = content.substr(1);
        }

        std::string messageCommand = "MESSAGE " + recipient + " " + content;
        send(clientSocket, messageCommand.c_str(), static_cast<int>(messageCommand.length()), 0);
    }

    void handleGroupMessage(const std::string& input) {
        std::istringstream iss(input);
        std::string command, groupIdStr, content;
        iss >> command >> groupIdStr;
        std::getline(iss, content);

        if (groupIdStr.empty() || content.empty()) {
            std::cout << "Usage: /group <group_id> <message>" << std::endl;
            return;
        }

        // Remove leading space from content
        if (!content.empty() && content[0] == ' ') {
            content = content.substr(1);
        }

        std::string messageCommand = "GROUP_MESSAGE " + groupIdStr + " " + content;
        send(clientSocket, messageCommand.c_str(), static_cast<int>(messageCommand.length()), 0);
    }

    void handleCreateGroup(const std::string& input) {
        std::istringstream iss(input);
        std::string command, groupName;
        iss >> command >> groupName;

        if (groupName.empty()) {
            std::cout << "Usage: /creategroup <group_name>" << std::endl;
            return;
        }

        std::string createCommand = "CREATE_GROUP " + groupName;
        send(clientSocket, createCommand.c_str(), static_cast<int>(createCommand.length()), 0);
    }

    void handleJoinGroup(const std::string& input) {
        std::istringstream iss(input);
        std::string command, groupIdStr;
        iss >> command >> groupIdStr;

        if (groupIdStr.empty()) {
            std::cout << "Usage: /joingroup <group_id>" << std::endl;
            return;
        }

        std::string joinCommand = "JOIN_GROUP " + groupIdStr;
        send(clientSocket, joinCommand.c_str(), static_cast<int>(joinCommand.length()), 0);
    }

    void handleListGroups() {
        std::string listCommand = "LIST_GROUPS";
        send(clientSocket, listCommand.c_str(), static_cast<int>(listCommand.length()), 0);
    }

    void handleRefreshGroups() {
        std::cout << "Refreshing group list..." << std::endl;
        std::string refreshCommand = "REFRESH_GROUPS";
        send(clientSocket, refreshCommand.c_str(), static_cast<int>(refreshCommand.length()), 0);
    }

    void handleLeaveGroup(const std::string& input) {
        std::istringstream iss(input);
        std::string command, groupIdStr;
        iss >> command >> groupIdStr;

        if (groupIdStr.empty()) {
            std::cout << "Usage: /leavegroup <group_id>" << std::endl;
            return;
        }

        std::string leaveCommand = "LEAVE_GROUP " + groupIdStr;
        send(clientSocket, leaveCommand.c_str(), static_cast<int>(leaveCommand.length()), 0);
    }

    void handleGroupInfo(const std::string& input) {
        std::istringstream iss(input);
        std::string command, groupIdStr;
        iss >> command >> groupIdStr;

        if (groupIdStr.empty()) {
            std::cout << "Usage: /groupinfo <group_id>" << std::endl;
            return;
        }

        std::string infoCommand = "GROUP_INFO " + groupIdStr;
        send(clientSocket, infoCommand.c_str(), static_cast<int>(infoCommand.length()), 0);
    }

    void handleMyGroups() {
        std::string myGroupsCommand = "MY_GROUPS";
        send(clientSocket, myGroupsCommand.c_str(), static_cast<int>(myGroupsCommand.length()), 0);
    }

    void handleStatus() {
        std::cout << "\n=== Connection Status ===" << std::endl;
        std::cout << "Username: " << username << std::endl;
        std::cout << "Connected: " << (connected ? "Yes" : "No") << std::endl;
        std::cout << "Server: 127.0.0.1:" << PORT << std::endl;
        std::cout << "=========================" << std::endl;
    }

    void clearScreen() {
        system("cls"); // Windows
        // system("clear"); // Linux/Mac
        showHelp();
    }

    void showHelp() {
        std::cout << "\n=== Essential Chat Commands ===" << std::endl;
        std::cout << "/dm <recipient> <message>     - Send direct message" << std::endl;
        std::cout << "/group <group_id> <message>   - Send group message" << std::endl;
        std::cout << "/creategroup <group_name>     - Create new group" << std::endl;
        std::cout << "/joingroup <group_id>         - Join existing group" << std::endl;
        std::cout << "/listgroups                   - List your groups" << std::endl;
        std::cout << "/refreshgroups                - Refresh group list" << std::endl;
        std::cout << "/help                         - Show essential commands" << std::endl;
        std::cout << "/commands                     - Show all commands" << std::endl;
        std::cout << "/quit                         - Exit chat" << std::endl;
        std::cout << "===============================" << std::endl;
    }

    void showAllCommands() {
        std::cout << "\n=== All Available Commands ===" << std::endl;
        std::cout << "\n--- Messaging ---" << std::endl;
        std::cout << "/dm <recipient> <message>     - Send direct message to user" << std::endl;
        std::cout << "/group <group_id> <message>   - Send message to group" << std::endl;

        std::cout << "\n--- Group Management ---" << std::endl;
        std::cout << "/creategroup <group_name>     - Create new group" << std::endl;
        std::cout << "/joingroup <group_id>         - Join existing group" << std::endl;
        std::cout << "/leavegroup <group_id>        - Leave a group" << std::endl;
        std::cout << "/listgroups                   - List all available groups" << std::endl;
        std::cout << "/mygroups                     - List groups you're member of" << std::endl;
        std::cout << "/refreshgroups                - Refresh group list from server" << std::endl;
        std::cout << "/groupinfo <group_id>         - Get group information" << std::endl;

        std::cout << "\n--- Utility ---" << std::endl;
        std::cout << "/status                       - Show connection status" << std::endl;
        std::cout << "/clear                        - Clear screen" << std::endl;
        std::cout << "/help                         - Show essential commands" << std::endl;
        std::cout << "/commands                     - Show this complete list" << std::endl;
        std::cout << "/quit or /exit                - Exit chat application" << std::endl;

        std::cout << "\n--- Examples ---" << std::endl;
        std::cout << "/dm Alice Hello there!        - Send 'Hello there!' to Alice" << std::endl;
        std::cout << "/creategroup ProjectTeam      - Create group named 'ProjectTeam'" << std::endl;
        std::cout << "/joingroup 1                  - Join group with ID 1" << std::endl;
        std::cout << "/group 1 Hello everyone!      - Send message to group 1" << std::endl;
        std::cout << "===============================" << std::endl;
    }

    void cleanup() {
        connected = false;
        if (clientSocket != INVALID_SOCKET) {
            closesocket(clientSocket);
        }
        WSACleanup();
    }
};

int main() {
    try {
        ChatClient client;
        client.run();
    }
    catch (const std::exception& e) {
        std::cerr << "Client error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
