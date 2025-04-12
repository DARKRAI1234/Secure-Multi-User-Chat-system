# Makefile for Secure Multi-User Chat System

# Compiler settings
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -pthread

# OpenSSL settings
OPENSSL_LIBS = -lcrypto -lssl

# Server settings
SERVER_SRC = server.cpp
SERVER_OBJ = $(SERVER_SRC:.cpp=.o)
SERVER_TARGET = chat_server

# Client settings
CLIENT_SRC = client.cpp
CLIENT_OBJ = $(CLIENT_SRC:.cpp=.o)
CLIENT_TARGET = chat_client

# Group handler library
GROUP_SRC = group_handler.cpp
GROUP_OBJ = $(GROUP_SRC:.cpp=.o)
GROUP_LIB = libgrouphandler.a

# Authentication library
AUTH_SRC = authentication.cpp
AUTH_OBJ = $(AUTH_SRC:.cpp=.o)
AUTH_LIB = libauthentication.a

# All targets
.PHONY: all clean

all: $(SERVER_TARGET) $(CLIENT_TARGET)

# Server build
$(SERVER_TARGET): $(SERVER_OBJ) $(GROUP_LIB) $(AUTH_LIB)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(OPENSSL_LIBS)

# Client build
$(CLIENT_TARGET): $(CLIENT_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(OPENSSL_LIBS)

# Group handler library
$(GROUP_LIB): $(GROUP_OBJ)
	ar rcs $@ $^

# Authentication library
$(AUTH_LIB): $(AUTH_OBJ)
	ar rcs $@ $^

# Object file compilation rules
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean up
clean:
	rm -f $(SERVER_OBJ) $(CLIENT_OBJ) $(GROUP_OBJ) $(AUTH_OBJ)
	rm -f $(SERVER_TARGET) $(CLIENT_TARGET) $(GROUP_LIB) $(AUTH_LIB)