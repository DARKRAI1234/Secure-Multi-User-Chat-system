@echo off
rem compile.bat - Batch file to compile the chat system on Windows

rem Set your OpenSSL paths here - adjust these to your actual installation paths
set OPENSSL_INCLUDE=C:\openssl-3.0\x64\include
set OPENSSL_LIB=C:\openssl-3.0\x64\lib

rem Compiler settings
set COMPILER=g++
set CFLAGS=-std=c++17 -Wall -Wextra

echo Checking for compiler...
where %COMPILER% > nul 2>&1
if %errorlevel% neq 0 (
    echo Error: %COMPILER% not found in PATH. Please install MinGW or adjust PATH.
    goto error
)

echo Creating build directory...
if not exist build mkdir build
if %errorlevel% neq 0 (
    echo Error: Failed to create build directory.
    goto error
)

rem Ensure build directory has proper permissions
icacls build /grant Everyone:(OI)(CI)F /T > nul 2>&1

echo Compiling all source files...
%COMPILER% %CFLAGS% -c authentication.cpp -I"%OPENSSL_INCLUDE%" -o build/authentication.o
if %errorlevel% neq 0 goto error

%COMPILER% %CFLAGS% -c group_handler.cpp -o build/group_handler.o
if %errorlevel% neq 0 goto error

%COMPILER% %CFLAGS% -c server.cpp -o build/server.o
if %errorlevel% neq 0 goto error

%COMPILER% %CFLAGS% -c client.cpp -o build/client.o
if %errorlevel% neq 0 goto error

echo Linking server executable...
%COMPILER% %CFLAGS% -o build/chat_server.exe build/server.o build/authentication.o build/group_handler.o -L"%OPENSSL_LIB%" -lcrypto -lssl -lws2_32
if %errorlevel% neq 0 goto error

echo Linking client executable...
%COMPILER% %CFLAGS% -o build/chat_client.exe build/client.o -lws2_32
if %errorlevel% neq 0 goto error

echo Compilation successful!
echo Executables can be found in the build directory.
goto end

:error
echo.
echo Compilation failed with error code %errorlevel%

:end