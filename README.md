# Secure Multi-User Chat System

A robust, real-time multi-user chat application built with C++ featuring secure user authentication, group management, and MySQL database integration. This system supports concurrent connections, real-time messaging, and comprehensive chat functionality.

## Features

### Security & Authentication
- Secure Password Hashing: SHA-256 with individual salt for each user
- User Registration & Login: Complete authentication system with database validation
- Session Management: Secure client-server session handling
- Input Validation: Protection against SQL injection and malicious inputs

### Real-Time Communication
- Direct Messaging: Private messages between users
- Group Chat: Create, join, and manage chat groups
- Multi-Client Support: Handles multiple concurrent connections
- Message Timestamps: All messages include accurate timestamps
- Real-Time Updates: Instant message delivery and group synchronization

### Advanced Features
- Thread-Safe Operations: Concurrent user support without conflicts
- Database Persistence: All data stored in MySQL with proper relationships
- Command Interface: Comprehensive set of chat commands with help system
- Group Management: Create, join, leave groups with member tracking
- Direct Database Connections: Optimized performance with reliable connectivity

## System Architecture

### Server Components
- **ChatServer**: Main server class handling client connections
- **Authentication**: Secure user management with password hashing
- **GroupHandler**: Complete group management system
- **ConnectionPool**: Database connection management (optional)

### Client Components
- **ChatClient**: Full-featured client with command interface
- **Real-time Messaging**: Threaded message handling
- **Command System**: Rich set of chat commands with help

### Database Schema
- **users**: User accounts with secure credential storage
- **chat_groups**: Group information and metadata
- **group_members**: Group membership tracking with relationships

## Requirements

### Software Requirements
- Windows 10/11
- Visual Studio 2019 or later
- MySQL Server 8.0 or later
- MySQL Connector C++ 9.3

### Hardware Requirements
- Minimum 4GB RAM
- Network connectivity for client-server communication
- Sufficient disk space for MySQL database

## Installation & Setup

### 1. Database Setup
-- Run the following in MySQL:
CREATE DATABASE chat_db;
-- Then execute Database/schema.sql


### 2. Configure Database Connection
Open `server.cpp` and modify the database configuration constants:


const std::string DB_HOST = "127.0.0.1"; // Your MySQL server IP
const int DB_PORT = 3306; // Your MySQL port
const std::string DB_USERNAME = "root"; // Your MySQL username
const std::string DB_PASSWORD = "your_password_here"; // *** CHANGE THIS ***
const std::string DB_NAME = "chat_db"; // Your database name


### 3. Build the Project
1. Open the solution file in Visual Studio
2. Set configuration to Release/x64
3. Build both Server and Client projects
4. Copy required MySQL DLLs to output directory

### 4. Required DLLs
Copy these files to your Release folder:
- mysqlcppconn-10-vs14.dll
- libcrypto-3-x64.dll (if using OpenSSL)
- libssl-3-x64.dll (if using OpenSSL)

## Usage

### Starting the Server
1. Run `Chat Server.exe`
2. Server will initialize database and listen on port 8080
3. Wait for "Chat server running on port 8080" message

### Connecting Clients
1. Run `Chat Client.exe` (can run multiple instances)
2. Choose Login or Register
3. Enter credentials
4. Start chatting!

## Chat Commands

### Essential Commands

/dm <recipient> <message> - Send direct message
/creategroup <group_name> - Create new group
/joingroup <group_id> - Join existing group
/listgroups - List all available groups
/help - Show essential commands
/quit - Exit chat


### Advanced Commands

/group <group_id> <message> - Send group message
/mygroups - Show groups you're member of
/groupinfo <group_id> - Get detailed group information
/leavegroup <group_id> - Leave a group
/refreshgroups - Refresh group list from server
/status - Show connection information
/commands - Show all available commands
/clear - Clear screen


## Project Structure

Secure-Multi-User-Chat-System/
├── Server/
│ ├── server.cpp # Main server implementation
│ ├── authentication.h/.cpp # User authentication system
│ ├── group_handler.h/.cpp # Group management system
│ ├── connectionpool.h/.cpp # Database connection handling
│ └── Chat_Server.vcxproj # Server project file
├── Client/
│ ├── client.cpp # Client application
│ └── Chat_Client.vcxproj # Client project file
├── Database/
│ └── schema.sql # MySQL database schema
├── .gitignore # Git ignore file
├── README.md # This file
└── Secure-Multi-User-Chat-System.sln # Solution file



## Database Schema

### Users Table

CREATE TABLE users (
id INT AUTO_INCREMENT PRIMARY KEY,
username VARCHAR(50) UNIQUE NOT NULL,
password_hash VARCHAR(64) NOT NULL,
salt VARCHAR(32) NOT NULL,
email VARCHAR(100),
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


### Chat Groups Table

CREATE TABLE chat_groups (
id INT AUTO_INCREMENT PRIMARY KEY,
group_name VARCHAR(100) NOT NULL,
created_by VARCHAR(50) NOT NULL,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


### Group Members Table

CREATE TABLE group_members (
group_id INT,
username VARCHAR(50),
joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
PRIMARY KEY (group_id, username),
FOREIGN KEY (group_id) REFERENCES chat_groups(id) ON DELETE CASCADE
);


## Development Features

### Security Implementation
- **Password Security**: SHA-256 hashing with unique salt per user
- **SQL Injection Prevention**: Prepared statements throughout
- **Session Management**: Secure client authentication tracking
- **Input Validation**: Comprehensive validation on all user inputs

### Performance Optimizations
- **Direct Database Connections**: Eliminates connection pool overhead
- **Thread-Safe Operations**: Mutex protection for shared resources
- **Efficient Memory Management**: Smart pointers and RAII principles
- **Optimized Queries**: Indexed database operations for better performance

### Networking Architecture
- **Winsock2 Implementation**: Robust Windows socket programming
- **Multi-threaded Server**: Each client handled in separate thread
- **Real-time Communication**: Instant message delivery
- **Connection Management**: Proper cleanup and error handling

## Troubleshooting

### Common Issues

#### Database Connection Errors
- Verify MySQL server is running
- Check database credentials in server.cpp
- Ensure MySQL Connector C++ DLLs are in output directory
- Confirm database and tables exist

#### DLL Not Found Errors
- Copy mysqlcppconn-10-vs14.dll to Release folder
- Add MySQL lib64 directory to system PATH
- Verify all required Visual C++ redistributables are installed

#### Client Connection Issues
- Ensure server is running on port 8080
- Check Windows Firewall settings
- Verify network connectivity between client and server
- Confirm server initialization completed successfully

### Build Issues
- Use Release configuration with x64 platform
- Verify MySQL Connector C++ paths in project properties
- Ensure OpenSSL libraries are properly linked
- Check Visual Studio version compatibility


### Development Setup
1. Fork the repository
2. Set up development environment with Visual Studio and MySQL
3. Make changes and test thoroughly
4. Submit pull request with detailed description


This chat system demonstrates advanced C++ programming concepts including network programming, database integration, multi-threading, and security implementation.
