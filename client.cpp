// client.cpp - Client implementation for Windows
#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

// Constants
const int DEFAULT_PORT = 8888;
const char* DEFAULT_SERVER = "127.0.0.1";
const int BUFFER_SIZE = 4096;

// Global variables
std::atomic<bool> clientRunning(true);

// Function to receive messages from server
void receiveMessages(SOCKET sock) {
    char buffer[BUFFER_SIZE];
    std::string partialMessage;
    
    while (clientRunning) {
        memset(buffer, 0, BUFFER_SIZE);
        int bytesReceived = recv(sock, buffer, BUFFER_SIZE - 1, 0);
        
        if (bytesReceived <= 0) {
            if (bytesReceived == 0) {
                std::cout << "Server disconnected" << std::endl;
            } else {
                std::cerr << "Error receiving message: " << WSAGetLastError() << std::endl;
            }
            clientRunning = false;
            break;
        }

        // Add received data to partial message
        partialMessage += std::string(buffer, bytesReceived);
        
        // Process complete messages
        size_t pos;
        while ((pos = partialMessage.find('\n')) != std::string::npos) {
            std::string message = partialMessage.substr(0, pos);
            std::cout << message << std::endl;  // Print complete message
            partialMessage = partialMessage.substr(pos + 1);
        }
    }
}

int main(int argc, char* argv[]) {
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed" << std::endl;
        return 1;
    }
    
    // Determine server address and port
    const char* serverIP = (argc > 1) ? argv[1] : DEFAULT_SERVER;
    int port = (argc > 2) ? std::stoi(argv[2]) : DEFAULT_PORT;
    
    // Create socket
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Error creating socket: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }
    
    // Set up server address
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    
    // Convert IP address from text to binary
    if (inet_pton(AF_INET, serverIP, &serverAddr.sin_addr) <= 0) {
        std::cerr << "Invalid address or address not supported" << std::endl;
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    
    // Connect to server
    if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Connection failed: " << WSAGetLastError() << std::endl;
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    
    std::cout << "Connected to server at " << serverIP << ":" << port << std::endl;
    
    // Start thread to receive messages
    std::thread receiveThread(receiveMessages, sock);
    
    // Main loop for sending messages
    while (clientRunning) {
        std::string message;
        std::getline(std::cin, message);
        
        if (message == "/quit") {
            clientRunning = false;
            break;
        }
        
        // Add newline to message
        message += '\n';
        
        if (send(sock, message.c_str(), message.length(), 0) == SOCKET_ERROR) {
            std::cerr << "Error sending message: " << WSAGetLastError() << std::endl;
            clientRunning = false;
            break;
        }
    }
    
    // Wait for receive thread to finish
    if (receiveThread.joinable()) {
        receiveThread.join();
    }
    
    // Close socket
    closesocket(sock);
    
    // Cleanup Winsock
    WSACleanup();
    
    std::cout << "Disconnected from server" << std::endl;
    
    return 0;
}