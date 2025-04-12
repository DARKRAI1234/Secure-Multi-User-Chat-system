@echo off
rem compile.bat - Batch file to compile the chat system on Windows

rem Set your OpenSSL paths here
set OPENSSL_INCLUDE=C:\openssl-3.0\x64\include
set OPENSSL_LIB=C:\openssl-3.0\x64\lib

rem Compiler settings
set COMPILER=g++
set CFLAGS=-std=c++17 -Wall -Wextra

echo Compiling authentication module...
%COMPILER% %CFLAGS% -c authentication.cpp -I"%OPENSSL_INCLUDE%"
if %errorlevel% neq 0 goto error

echo Compiling group handler...
%COMPILER% %CFLAGS% -c group_handler.cpp
if %errorlevel% neq 0 goto error

echo Creating libraries...
ar rcs libauthentication.a authentication.o
if %errorlevel% neq 0 goto error
ar rcs libgrouphandler.a group_handler.o
if %errorlevel% neq 0 goto error

echo Compiling server...
%COMPILER% %CFLAGS% -c server.cpp -I"%OPENSSL_INCLUDE%"
if %errorlevel% neq 0 goto error
%COMPILER% %CFLAGS% -o chat_server.exe server.o libauthentication.a libgrouphandler.a -L"%OPENSSL_LIB%" -lcrypto -lssl -lws2_32
if %errorlevel% neq 0 goto error

echo Compiling client...
%COMPILER% %CFLAGS% -c client.cpp -I"%OPENSSL_INCLUDE%"
if %errorlevel% neq 0 goto error
%COMPILER% %CFLAGS% -o chat_client.exe client.o -L"%OPENSSL_LIB%" -lcrypto -lssl -lws2_32
if %errorlevel% neq 0 goto error

echo Compilation successful!
goto end

:error
echo Compilation failed with error code %errorlevel%

:end