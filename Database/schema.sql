-- Chat System Database Schema
-- Multi-User Chat System with Secure Authentication and Group Management

CREATE DATABASE IF NOT EXISTS chat_db;
USE chat_db;

-- Users table for secure authentication
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(64) NOT NULL,
    salt VARCHAR(32) NOT NULL,
    email VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Chat groups table (renamed from 'groups' to avoid MySQL reserved keyword)
CREATE TABLE IF NOT EXISTS chat_groups (
    id INT AUTO_INCREMENT PRIMARY KEY,
    group_name VARCHAR(100) NOT NULL,
    created_by VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Group members table with foreign key relationships
CREATE TABLE IF NOT EXISTS group_members (
    group_id INT,
    username VARCHAR(50),
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (group_id, username),
    FOREIGN KEY (group_id) REFERENCES chat_groups(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create indexes for better performance
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_groups_created_by ON chat_groups(created_by);
CREATE INDEX idx_members_username ON group_members(username);
CREATE INDEX idx_members_group_id ON group_members(group_id);

-- Display table structure for verification
DESCRIBE users;
DESCRIBE chat_groups;
DESCRIBE group_members;

