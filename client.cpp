// client.cpp - Client-side implementation
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    #define close(s) closesocket(s)
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <unistd.h>
    #include <arpa/inet.h>
#endif


#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>

// Configuration constants
const int BUFFER_SIZE = 1024;
const std::string DEFAULT_SERVER = "127.0.0.1";
const int DEFAULT_PORT = 8888;

class ChatClient {
private:
    int clientSocket;
    std::string serverIP;
    int serverPort;
    std::atomic<bool> running;
    std::thread receiveThread;
    std::mutex consoleMutex;
    
    void receiveMessages() {
        char buffer[BUFFER_SIZE];
        
        while (running) {
            memset(buffer, 0, BUFFER_SIZE);
            int bytesRead = recv(clientSocket, buffer, BUFFER_SIZE - 1, 0);
            
            if (bytesRead <= 0) {
                if (running) {
                    std::lock_guard<std::mutex> lock(consoleMutex);
                    std::cout << "\nDisconnected from server. Press Enter to exit." << std::endl;
                    running = false;
                }
                break;
            }
            
            std::lock_guard<std::mutex> lock(consoleMutex);
            std::cout << buffer;
        }
    }
    
public:
    ChatClient(const std::string& serverIP = DEFAULT_SERVER, int serverPort = DEFAULT_PORT)
        : serverIP(serverIP), serverPort(serverPort), clientSocket(-1), running(false) {}
    
    ~ChatClient() {
        disconnect();
    }
    
    bool connect() {
        // Create socket
        clientSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (clientSocket == -1) {
            std::cerr << "Error creating socket" << std::endl;
            return false;
        }
        
        // Setup server address
        struct sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(serverPort);
        
        if (inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr) <= 0) {
            std::cerr << "Invalid address or address not supported" << std::endl;
            close(clientSocket);
            return false;
        }
        
        // Connect to server
        if (::connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
            std::cerr << "Connection failed" << std::endl;
            close(clientSocket);
            return false;
        }
        
        running = true;
        
        // Start receiving messages in a separate thread
        receiveThread = std::thread(&ChatClient::receiveMessages, this);
        
        return true;
    }
    
    void disconnect() {
        running = false;
        
        if (clientSocket != -1) {
            close(clientSocket);
            clientSocket = -1;
        }
        
        if (receiveThread.joinable()) {
            receiveThread.join();
        }
    }
    
    void run() {
        std::string message;
        
        std::cout << "Connected to server. Type your messages (or /quit to exit)" << std::endl;
        displayHelp();
        
        while (running) {
            std::getline(std::cin, message);
            
            if (message == "/quit") {
                break;
            }
            
            if (message == "/help") {
                displayHelp();
                continue;
            }
            
            if (!message.empty()) {
                if (send(clientSocket, message.c_str(), message.length(), 0) < 0) {
                    std::lock_guard<std::mutex> lock(consoleMutex);
                    std::cout << "Failed to send message" << std::endl;
                    break;
                }
            }
        }
        
        disconnect();
    }
    
    void displayHelp() {
        std::cout << "\n--- Chat Client Help ---" << std::endl;
        std::cout << "/register username:password - Create a new account" << std::endl;
        std::cout << "/login username:password - Log in to your account" << std::endl;
        std::cout << "/logout - Log out from your account" << std::endl;
        std::cout << "/msg username message - Send a private message" << std::endl;
        std::cout << "/broadcast message - Send a message to all online users" << std::endl;
        std::cout << "/create_group groupname - Create a new group" << std::endl;
        std::cout << "/join_group groupname - Join an existing group" << std::endl;
        std::cout << "/leave_group groupname - Leave a group" << std::endl;
        std::cout << "/group_msg groupname message - Send a message to a group" << std::endl;
        std::cout << "/list_users - Show online users" << std::endl;
        std::cout << "/list_groups - Show available groups" << std::endl;
        std::cout << "/help - Show this help message" << std::endl;
        std::cout << "/quit - Exit the client" << std::endl;
        std::cout << "------------------------\n" << std::endl;
    }
};

// Signal handler to handle Ctrl+C
void signalHandler(int signal) {
    std::cout << "\nReceived interrupt signal. Exiting..." << std::endl;
    exit(signal);
}

int main(int argc, char* argv[]) {
    #ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "WSAStartup failed" << std::endl;
            return 1;
        }
    #endif
    std::string serverIP = DEFAULT_SERVER;
    int serverPort = DEFAULT_PORT;
    
    // Parse command-line arguments
    if (argc >= 2) {
        serverIP = argv[1];
    }
    
    if (argc >= 3) {
        serverPort = std::stoi(argv[2]);
    }
    
    // Set up signal handling
    signal(SIGINT, signalHandler);
    
    std::cout << "Chat Client starting..." << std::endl;
    std::cout << "Connecting to server at " << serverIP << ":" << serverPort << std::endl;
    
    ChatClient client(serverIP, serverPort);
    
    if (!client.connect()) {
        std::cerr << "Failed to connect to server" << std::endl;
        return 1;
    }
    
    client.run();
    
    std::cout << "Chat Client closed" << std::endl;
    #ifdef _WIN32
        WSACleanup();
    #endif
    
    return 0;
}