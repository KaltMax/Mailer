// C
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <string.h>
#include <sysexits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <fcntl.h>
#include <termios.h>
#include <ldap.h>
// C++
#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <thread>
#include <mutex>
#include <chrono>
#include <map>

using namespace std;

//----------------------------------------------------------------------
// Constants
//----------------------------------------------------------------------

const unsigned int BUFFER_SIZE = 65536;
const size_t MAX_MESSAGE_SIZE = 65536;

const string server_welcome = "Welcome to myserver!\r\nPlease login...\r\n";
const string server_ok = "OK\r\n";

//----------------------------------------------------------------------
// Globals
//----------------------------------------------------------------------

bool abort_requested = false;
int server_socket = -1;
int new_connection_socket = -1;
in_port_t server_port = 0;
string mail_spool_directory;
vector<thread> client_threads;
mutex threads_mutex;
vector<int*> client_sockets;
mutex sockets_mutex;

// Variables for blocking a client-IP for 60 seconds after 3 failed attempts
map<string, pair<int, chrono::steady_clock::time_point>> loginAttempts;
const int MAX_ATTEMPTS = 3;
const int BLOCK_DURATION_SECONDS = 60;
mutex loginAttemptsMutex; // Mutex to protect access to loginAttempts map

//----------------------------------------------------------------------
// Function prototypes
//----------------------------------------------------------------------

// Authorization-Functions
bool checkIfBlocked(int* client_socket, const string& client_ip);
bool loginUser(int* client_socket, const string& client_ip, const string& client_message, string& userid);
bool authenticateWithLDAP(const string& username, const string& password);
// ClientCommunication-Functions
void sendWelcomeMessage(int* client_socket);
void mainClientCommunicationLoop(int* client_socket, const string& client_ip);
int clientCommunication(int* client_socket, sockaddr_in client_address);
int handleSend(int* client_socket, const string& client_message, const string& sender);
int handleList(int* client_socket, const string& client_message, const string& userid);
int handleRead(int* client_socket, const string& client_message, const string& userid);
int handleDelete(int* client_socket, const string& client_message, const string& userid);
void handleQuit(int* client_socket, const string& client_ip);
void signalHandler(int signal);
// Helper-Functions
bool openDirectoryAndApplyLock(const string& directory_path, int lock_type, int& dir_fd);
bool saveMessageToFile(const string &receiver, const string &sender, const string &subject, const string &message_body);
bool isValidUsername(const string& username);
string getIPAddress(struct sockaddr_in client_address);

//----------------------------------------------------------------------
//  M A I N
//----------------------------------------------------------------------

auto main(int argc, char **argv) -> int 
{
    int return_code = EX_OK; // EX_OK is defined in sysexits.h
    socklen_t addrlen;
    struct sockaddr_in address, client_address;
    int reuse_value = 1;
    int status = -1;

    // Set signal handler
    if (signal(SIGINT, signalHandler) == SIG_ERR) 
    {
        cerr << "Error setting signal handler: " << strerror(errno) << " (" << errno << ")\n";
        return(EX_UNAVAILABLE);
    }

    // Check if used correctly
    if(argc < 3) 
    {
      cerr << "How to start the server correctly: \"./twmailer-server <port> <mail-spool-directoryname>" << "\n";
      return_code = EX_OSERR;
      exit(return_code);
    }

    // Set port and mailbox directory
    server_port = stoi(argv[1]);
    mail_spool_directory = argv[2];

    // Create the mail_spool_directory if it doesn't exist
    if (!filesystem::exists(mail_spool_directory)) 
    {
        try 
        {
            if (filesystem::create_directories(mail_spool_directory)) 
            {
                cout << "Mail spool directory created at: " << mail_spool_directory << "\n";
            }
        } 
        catch (const filesystem::filesystem_error& e) 
        {
            cerr << "Error: Unable to create mail spool directory: " << e.what() << "\n";
            return EX_OSERR;
        }
    }

    // Create socket descriptor (i.e. request descriptor from operating system
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) 
    {
        cerr << "Error getting socket descriptor: " << strerror(errno) << " (" << errno << ")\n";
        return(EX_CANTCREAT);
    }

    // Set socket options
    status = setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &reuse_value, sizeof(reuse_value));
    if (status == -1) 
    {
        cerr << "Error setting socket options: " << strerror(errno) << " (" << errno << ")\n";
        return(EX_OSERR);
    }

    // Initialise address structure with listening address and port
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(server_port);

    // Bind socket to address
    status = bind(server_socket, (struct sockaddr*)&address, sizeof(address));
    if (status == -1) 
    {
        cerr << "Error binding socket: " << strerror(errno) << " (" << errno << ")\n";
        return(EX_UNAVAILABLE);
    }

    // Allow connections 
    status = listen(server_socket, 20);
    if (status == -1) 
    {
        cerr << "Error enabling listening mode: " << strerror(errno) << " (" << errno << ")\n";
        return(EX_UNAVAILABLE);
    }

    // ----------------------------------------------------------------------
    // Main server loop - here clients are accepted and directed to work functions
    // ----------------------------------------------------------------------
    while (!abort_requested) 
    {
        cout << "Waiting for new connections...\n";
        addrlen = sizeof(struct sockaddr_in);
        int* client_socket = new int(accept(server_socket, (struct sockaddr*)&client_address, &addrlen));

        if (*client_socket == -1) 
        {
            if (abort_requested) break;
            cerr << "Error during accept() call: " << strerror(errno) << "\n";
            delete client_socket; // Free memory if socket creation fails
            continue;
        }

        // Add the client socket to the list of active sockets
        {
            lock_guard<mutex> lock(sockets_mutex);
            client_sockets.push_back(client_socket);
        }

        // Start a new thread for each client connection
        {
            lock_guard<mutex> lock(threads_mutex);
            client_threads.emplace_back([client_socket, client_address]() {
                clientCommunication(client_socket, client_address);

                // Remove client socket from the list upon disconnection
                {
                    lock_guard<mutex> lock(sockets_mutex);
                    auto it = remove(client_sockets.begin(), client_sockets.end(), client_socket);
                    if (it != client_sockets.end()) {
                        client_sockets.erase(it);
                    }
                }
                close(*client_socket);
                delete client_socket;  // Free memory after the socket is closed
            });
        }

        cout << "Client connected from " << inet_ntoa(client_address.sin_addr) << "\n";
    }

    // Signal handler will close all threads upon receiving SIGINT
    for (auto& thread : client_threads) 
    {
        if (thread.joinable()) 
            thread.join();
    }
    client_threads.clear();

    // Close server socket
    if (server_socket != -1) 
        close(server_socket);

    return EX_OK;
}

//----------------------------------------------------------------------
// Client Communication Functions
//----------------------------------------------------------------------

int clientCommunication(int* client_socket, sockaddr_in client_address) 
{
    string client_ip = inet_ntoa(client_address.sin_addr);

    // Check if the client IP is blocked
    if (checkIfBlocked(client_socket, client_ip)) {
        return EX_OK; // Exit if IP is blocked
    }

    // Send welcome message to client
    sendWelcomeMessage(client_socket);

    // Proceed with main communication loop after successful login
    mainClientCommunicationLoop(client_socket, client_ip);

    return EX_OK;
}

// ---------------------------------------------------------------------
// Helper functions for communicating with client
// ---------------------------------------------------------------------

void sendWelcomeMessage(int* client_socket)
{   
    int status;
    status = send(*client_socket, server_welcome.c_str(), server_welcome.length(), 0);
    if (status == -1) 
    {
        cerr << "Error while sending welcome message to client: " << strerror(errno) << " (" << errno << ")\n";
        status = send(*client_socket, "ERR\n", 3, 0);
    }
}

bool checkIfBlocked(int* client_socket, const string& client_ip) 
{
    auto currentTime = chrono::steady_clock::now();
    lock_guard<mutex> lock(loginAttemptsMutex);

    if (loginAttempts.find(client_ip) != loginAttempts.end()) 
    {
        auto [attempts, blockTime] = loginAttempts[client_ip];

        // Check if the block time has expired
        if (attempts >= MAX_ATTEMPTS && chrono::duration_cast<chrono::seconds>(currentTime - blockTime).count() < BLOCK_DURATION_SECONDS) 
        {
            send(*client_socket, "ERR\n", 4, 0);
            close(*client_socket);
            return true; // IP is still blocked
        } 
        else if (chrono::duration_cast<chrono::seconds>(currentTime - blockTime).count() >= BLOCK_DURATION_SECONDS) 
        {
            // Block time has passed, reset the counter for this IP
            loginAttempts.erase(client_ip);
        }
    }
    return false; // IP is not blocked
}

bool loginUser(int* client_socket, const string& client_ip, const string& client_message, string& userid) 
{
    // Create a stream from client_message to parse credentials
    istringstream stream(client_message);
    string command, user_pw;
    
    // The first line should be "LOGIN"
    getline(stream, command);
    if (command != "LOGIN") {
        cerr << "Expected LOGIN command.\n";
        send(*client_socket, "ERR\n", 4, 0);
        return false;
    }

    // Extract username and password from the next lines
    getline(stream, userid);
    getline(stream, user_pw);

    // Validate username and password
    if (!isValidUsername(userid))
    {
        cerr << "Invalid username format.\n";
        send(*client_socket, "ERR\n", 4, 0);
        return false;
    }

    if (user_pw.empty()) 
    {
        cerr << "Password is empty.\n";
        send(*client_socket, "ERR\n", 4, 0);
        return false;
    }

    // Check if the client IP is blocked
    if (checkIfBlocked(client_socket, client_ip)) 
    {
        return false; // Exit if IP is blocked
    }
    
    // Authenticate using LDAP or predefined test credentials
    if (authenticateWithLDAP(userid, user_pw))
    {
        send(*client_socket, "OK\n", 3, 0);
        
        // Reset login attempts for successful login
        lock_guard<mutex> lock(loginAttemptsMutex);
        loginAttempts.erase(client_ip);  
        return true;  // Login successful
    } 
    else 
    {
        // Handle failed attempt
        lock_guard<mutex> lock(loginAttemptsMutex);
        int attempts = (loginAttempts.find(client_ip) != loginAttempts.end()) ? loginAttempts[client_ip].first + 1 : 1;
        loginAttempts[client_ip] = {attempts, chrono::steady_clock::now()};
        cerr << "Login attempt " << attempts << " failed for IP: " << client_ip << "\n";
        send(*client_socket, "ERR\n", 4, 0);

        if (attempts >= MAX_ATTEMPTS) 
        {
            cerr << "IP " << client_ip << " is now blocked for " << BLOCK_DURATION_SECONDS << " seconds.\n";
            shutdown(*client_socket, SHUT_RDWR);
            close(*client_socket);
            return false; // Login failed and IP is blocked
        }
    }

    return false; // Login failed
}


bool authenticateWithLDAP(const string& username, const string& pw)
{

    const char* ldapUri = ""; // Enter LDAP server URI here
    const int ldapVersion = LDAP_VERSION3;
    LDAP* ldapHandle;
    int return_code;

    int n = pw.length();
    char password[n+1];
    strcpy(password, pw.c_str());

    // Initialize LDAP
    return_code = ldap_initialize(&ldapHandle, ldapUri);
    if (return_code != LDAP_SUCCESS) 
    {
        cerr << "LDAP initialization failed: " << ldap_err2string(return_code) << "\n";
        return false;
    }

    // Set LDAP protocol version
    return_code = ldap_set_option(ldapHandle, LDAP_OPT_PROTOCOL_VERSION, &ldapVersion);
    if (return_code != LDAP_OPT_SUCCESS)
    {
        cerr << "ldap_set_option(PROTOCOL_VERSION): " << ldap_err2string(return_code) << "\n";
        ldap_unbind_ext_s(ldapHandle, NULL, NULL);
        return false;
    }

    // Prepare the user DN for binding
    char ldapBindUser[256];
    snprintf(ldapBindUser, sizeof(ldapBindUser), "uid=%s,ou=people,dc=technikum-wien,dc=at", username.c_str());
    BerValue bindCredentials;
    bindCredentials.bv_val = (char*) password;
    bindCredentials.bv_len = strlen(password);
    BerValue* servercredp;

    // Attempt to bind with provided credentials
    return_code = ldap_sasl_bind_s(ldapHandle, ldapBindUser, LDAP_SASL_SIMPLE, &bindCredentials, NULL, NULL, &servercredp);
    ldap_unbind_ext_s(ldapHandle, NULL, NULL);  // Clean up LDAP handle

    // Return true if authentication was successful, false otherwise
    if (return_code == LDAP_SUCCESS) 
    {
        return true;
    }
    else 
    {
        cerr << "LDAP bind error: " << ldap_err2string(return_code) << "\n";
        return false;
    }
}

void mainClientCommunicationLoop(int* client_socket, const string& client_ip) 
{
    char buffer[BUFFER_SIZE];
    string client_message;
    int size, status;
    string userid;
    bool is_logged_in = false;

    while (true)
    {
        // Check if client IP is blocked
        if (checkIfBlocked(client_socket, client_ip))
        {
            break;
        }

        size = recv(*client_socket, buffer, BUFFER_SIZE - 1, 0);

        if (abort_requested) 
        {
            break;
        }

        if (size == -1) 
        {
            cerr << "Error during recv() call: " << strerror(errno) << " (" << errno << ")\n";
            break;
        }

        // Client disconnected
        if (size == 0)
        {
            cout << "Client disconnected unexpectedly\n";
            break;
        }

        // Null-terminate the received data and append to client_message
        buffer[size] = '\0';
        client_message.append(buffer, size);

        // Check if the accumulated message exceeds the maximum size
        if (client_message.size() > MAX_MESSAGE_SIZE)
        {
            cerr << "Message from client exceeds maximum size limit.\n";

            // Send error response to client
            send(*client_socket, "ERR\n", 4, 0);

            // Clear the oversized message to allow the client to continue
            client_message.clear();
            continue;
        }

        // Process the message if it's complete (ends with '\n')
        if (!client_message.empty() && client_message.back() == '\n')
        {
            // Handle not logged-in state
            if (!is_logged_in) 
            {
                if (client_message.rfind("LOGIN", 0) == 0) 
                {
                    if (loginUser(client_socket, client_ip, client_message, userid))
                    {
                        is_logged_in = true;
                    }
                }
                else if (client_message.rfind("QUIT", 0) == 0) 
                {
                    handleQuit(client_socket, client_ip);
                    break; 
                }
                else 
                {
                    cerr << "User not logged in; only LOGIN or QUIT commands allowed.\n";
                    send(*client_socket, "ERR\n", 4, 0);
                }

                client_message.clear(); // Clear the processed message
                continue;
            }

            // Process commands after login
            if (client_message.rfind("SEND", 0) == 0) 
            {
                status = handleSend(client_socket, client_message, userid);
            } 
            else if (client_message.rfind("LIST", 0) == 0) 
            {
                status = handleList(client_socket, client_message, userid);
            } 
            else if (client_message.rfind("READ", 0) == 0) 
            {
                status = handleRead(client_socket, client_message, userid);
            } 
            else if (client_message.rfind("DEL", 0) == 0) 
            {
                status = handleDelete(client_socket, client_message, userid);
            } 
            else if (client_message.rfind("QUIT", 0) == 0)
            {
                handleQuit(client_socket, client_ip);
                break; // Client requested to quit
            }
            else
            {
                cerr << "Unknown command received from client.\n";
                send(*client_socket, "ERR\n", 4, 0);
            }

            if (status == -1) 
            {
                cerr << "Error handling command: " << strerror(errno) << "\n";
                break;
            }

            client_message.clear(); // Clear the processed message
        }
    }

    // Clean up the socket
    shutdown(*client_socket, SHUT_RDWR);
    close(*client_socket);
}

//----------------------------------------------------------------------
// Functions for handling the client commands
//----------------------------------------------------------------------

int handleSend(int* client_socket, const string& client_message, const string& sender)
{
    string receiver, subject, message_body;
    istringstream stream(client_message);
    int status = 0;

    // Step 1: Check if the message starts with "SEND"
    string command;
    getline(stream, command);
    if (command != "SEND")
    {
        cerr << "Invalid command. Expected 'SEND'\n";
        status = send(*client_socket, "ERR\n", 4, 0);
        return status;
    }

    // Step 2: Parse the receiver, and subject
    getline(stream, receiver);      // Third line is the receiver
    getline(stream, subject);       // Fourth line is the subject

    // Validate the subject length (max 80 characters)
    if (subject.length() > 80) 
    {
        cerr << "Subject exceeds the maximum allowed length of 80 characters.\n";
        status = send(*client_socket, "ERR\n", 4, 0);
        return status;
    }

    // Step 3: Read the message body line by line until a line with only a "." is found => end of message
    string line;
    while (getline(stream, line)) 
    {
        if (line == ".")
        {
            break; // End of the message body
        }
        message_body += line + "\n";     // Append each line of the message to the body
    }

    // Step 4: Save the message to the receiver's inbox directory
    if(!saveMessageToFile(receiver, sender, subject, message_body))
    {
        cerr << "Error saving message.\n";
        status = send(*client_socket, "ERR\n", 4, 0);
        return status;
    }

    // Step 5: Send "OK" response to the client after saving the message
    status = send(*client_socket, "OK\n", 3, 0);
    return status;
}

int handleList(int* client_socket, const string& client_message, const string& userid)
{
    int status = 0;

    // Check if the message starts with "LIST"
    istringstream stream(client_message);
    string command;
    getline(stream, command);
    if (command != "LIST")
    {
        cerr << "Invalid command. Expected 'LIST'\n";
        status = send(*client_socket, "ERR\n", 4, 0);
        return status;
    }

    // Path to the user's inbox directory
    string inbox_dir_path = mail_spool_directory + "/" + userid + "_inbox";

    // Check if the inbox directory exists
    if (!filesystem::exists(inbox_dir_path) || !filesystem::is_directory(inbox_dir_path))
    {
        status = send(*client_socket, "ERR\n", 4, 0);
        if (status == -1)
        {
            cerr << "Error sending '0' message for no inbox found.\n";
        }
        return status;
    }

    // Open the inbox directory and apply a shared lock
    int inbox_dir_fd = open(inbox_dir_path.c_str(), O_RDONLY);
    if(!openDirectoryAndApplyLock(inbox_dir_path, LOCK_EX, inbox_dir_fd))
    {
        status = send(*client_socket, "ERR\n", 4, 0);
        return status;
    }

    // Get a list of message files in the inbox directory
    vector<filesystem::path> message_files;
    for (const auto& entry : filesystem::directory_iterator(inbox_dir_path))
    {
        if (entry.is_regular_file())
        {
            message_files.push_back(entry.path());
        }
    }

    // Sort the message files (optional, depending on desired order)
    sort(message_files.begin(), message_files.end());

    int message_count = message_files.size();
    string message_list = "";

    // Read each message file to extract the subject
    int index = 1;
    for (const auto& message_file_path : message_files)
    {
        ifstream message_file(message_file_path);
        if (!message_file.is_open())
        {
            cerr << "Error: Unable to open message file: " << message_file_path << endl;
            continue; // Skip this message file
        }

        string line;
        string subject = "(No Subject)";
        while (getline(message_file, line))
        {
            if (line.find("Subject: ") == 0)
            {
                subject = line.substr(9); // Extract the subject text
                break;
            }
        }
        message_file.close();

        message_list += to_string(index) + ": " + subject + "\n";
        index++;
    }

    // Release the lock on the inbox directory
    flock(inbox_dir_fd, LOCK_UN);
    close(inbox_dir_fd);

    // Send the message count followed by the list of subjects
    string message_count_str = to_string(message_count) + " Messages in your inbox:\n";
    status = send(*client_socket, message_count_str.c_str(), message_count_str.length(), 0);  // Capture the result of send
    if (status == -1)
    {
        cerr << "Error sending message count.\n";
        return status;
    }

    status = send(*client_socket, message_list.c_str(), message_list.length(), 0);  // Capture the result of send
    if (status == -1)
    {
        cerr << "Error sending message list.\n";
    }
    return status;
}

int handleRead(int* client_socket, const string& client_message, const string& userid)
{
    int message_number;
    int status = 0;

    // Check if the message starts with "READ"
    istringstream stream(client_message);
    string command;
    getline(stream, command);
    if (command != "READ")
    {
        cerr << "Invalid command. Expected 'READ'\n";
        status = send(*client_socket, "ERR\n", 4, 0);
        return status;
    }

    // Extract message_number from client_message
    string message_number_str;
    getline(stream, message_number_str); // Second line: message number

    // Validate the message number
    istringstream ss(message_number_str);
    if (!(ss >> message_number) || message_number <= 0) {
        cerr << "Invalid message number format or message number is not positive.\n";
        status = send(*client_socket, "ERR\n", 4, 0);
        return status;
    }

    // Path to the user's inbox directory
    string inbox_dir_path = mail_spool_directory + "/" + userid + "_inbox";

    // Check if the inbox directory exists
    if (!filesystem::exists(inbox_dir_path) || !filesystem::is_directory(inbox_dir_path))
    {
        cerr << "Inbox not found for user: " << userid << "\n";
        status = send(*client_socket, "ERR\n", 4, 0);
        return status;
    }

    // Open the inbox directory and apply a shared lock
    int inbox_dir_fd = open(inbox_dir_path.c_str(), O_RDONLY);
    if(!openDirectoryAndApplyLock(inbox_dir_path, LOCK_EX, inbox_dir_fd))
    {
        status = send(*client_socket, "ERR\n", 4, 0);
        return status;
    }

    // Get a list of message files in the inbox directory
    vector<filesystem::path> message_files;
    for (const auto& entry : filesystem::directory_iterator(inbox_dir_path))
    {
        if (entry.is_regular_file())
        {
            message_files.push_back(entry.path());
        }
    }

    // Sort the message files (optional, depending on desired order)
    sort(message_files.begin(), message_files.end());

    // Check if the message number is valid
    if (message_number > static_cast<int>(message_files.size()))
    {
        cerr << "Message number out of range.\n";

        // Unlock and close the directory before returning
        flock(inbox_dir_fd, LOCK_UN);
        close(inbox_dir_fd);

        status = send(*client_socket, "ERR\n", 4, 0);
        return status;
    }

    // Get the file path for the requested message
    filesystem::path message_file_path = message_files[message_number - 1];

    // Open and lock the specific message file for reading
    int message_file_fd = open(message_file_path.c_str(), O_RDONLY);
    if (message_file_fd == -1)
    {
        cerr << "Error: Unable to open message file.\n";

        // Unlock and close the directory before returning
        flock(inbox_dir_fd, LOCK_UN);
        close(inbox_dir_fd);

        status = send(*client_socket, "ERR\n", 4, 0);
        return status;
    }

    if (flock(message_file_fd, LOCK_SH) == -1)
    {
        cerr << "Error: Unable to lock message file for reading.\n";
        
        // Unlock and close the directory and file descriptors
        close(message_file_fd);
        flock(inbox_dir_fd, LOCK_UN);
        close(inbox_dir_fd);

        status = send(*client_socket, "ERR\n", 4, 0);
        return status;
    }

    // Read the entire message content
    ifstream message_file(message_file_path);
    if (!message_file.is_open())
    {
        cerr << "Error: Unable to open message file for reading.\n";

        // Unlock and close all descriptors
        flock(message_file_fd, LOCK_UN);
        close(message_file_fd);
        flock(inbox_dir_fd, LOCK_UN);
        close(inbox_dir_fd);

        status = send(*client_socket, "ERR\n", 4, 0);
        return status;
    }

    stringstream buffer;
    buffer << message_file.rdbuf();
    string full_message = buffer.str();
    message_file.close();

    // Unlock and close all descriptors after reading
    flock(message_file_fd, LOCK_UN);
    close(message_file_fd);
    flock(inbox_dir_fd, LOCK_UN);
    close(inbox_dir_fd);

    // Send the message to the client
    status = send(*client_socket, full_message.c_str(), full_message.length(), 0);

    return status;
}

int handleDelete(int* client_socket, const string& client_message, const string& userid)
{
    int message_number;
    int status = 0;

    // Check if the message starts with "DEL"
    istringstream stream(client_message);
    string command;
    getline(stream, command);
    if (command != "DEL")
    {
        cerr << "Invalid command. Expected 'DEL'\n";
        status = send(*client_socket, "ERR\n", 4, 0);
        return status;
    }
    // Extract username and message_number from client_message
    string message_number_str;
    getline(stream, message_number_str);   // Third line: message number (string)

    // Validate the message number
    istringstream ss(message_number_str);
    if (!(ss >> message_number) || message_number <= 0)
    {
        cerr << "Invalid message number format or message number is not positive.\n";
        status = send(*client_socket, "ERR\n", 4, 0);
        return status;
    }

    // Path to the user's inbox directory
    string inbox_dir_path = mail_spool_directory + "/" + userid + "_inbox";

    // Check if the inbox directory exists
    if (!filesystem::exists(inbox_dir_path) || !filesystem::is_directory(inbox_dir_path))
    {
        cerr << "Inbox not found for user: " << userid << "\n";
        status = send(*client_socket, "ERR\n", 4, 0);
        if (status == -1)
        {
            cerr << "Error sending 'ERR' message for missing inbox.\n";
        }
        return status;
    }

    // Open the inbox directory and apply an exclusive lock
    int inbox_dir_fd = open(inbox_dir_path.c_str(), O_RDONLY);
    if(!openDirectoryAndApplyLock(inbox_dir_path, LOCK_EX, inbox_dir_fd))
    {
        status = send(*client_socket, "ERR\n", 4, 0);
        return status;
    }

    // Get a list of message files in the inbox directory
    vector<filesystem::path> message_files;
    for (const auto& entry : filesystem::directory_iterator(inbox_dir_path))
    {
        if (entry.is_regular_file())
        {
            message_files.push_back(entry.path());
        }
    }

    // Sort the message files (optional, depending on desired order)
    sort(message_files.begin(), message_files.end());

    // Check if the message number is valid
    if (message_number > static_cast<int>(message_files.size()))
    {
        cerr << "Message number out of range.\n";

        // Unlock and close the directory before returning
        flock(inbox_dir_fd, LOCK_UN);
        close(inbox_dir_fd);

        status = send(*client_socket, "ERR\n", 4, 0);
        return status;
    }

    // Get the file path for the message to delete
    filesystem::path message_file_path = message_files[message_number - 1];

    // Delete the message file
    try
    {
        filesystem::remove(message_file_path);
        status = send(*client_socket, "OK\n", 3, 0);  // Send success response
        if (status == -1)
        {
            cerr << "Error sending 'OK' message after deletion.\n";
        }
    }
    catch (const filesystem::filesystem_error& e)
    {
        cerr << "Error deleting message file: " << e.what() << "\n";
        status = send(*client_socket, "ERR\n", 4, 0);  // Send error response if deletion fails
        if (status == -1)
        {
            cerr << "Error sending 'ERR' message after deletion failure.\n";
        }

        // Unlock and close the directory before returning
        flock(inbox_dir_fd, LOCK_UN);
        close(inbox_dir_fd);

        return status;
    }
    
    // Unlock and close the directory before returning
    flock(inbox_dir_fd, LOCK_UN);
    close(inbox_dir_fd);
    return status;
}

void handleQuit(int* client_socket, const string& client_ip)
{
    // Send a "Goodbye" message or simply acknowledge the QUIT request
    string goodbye_message = "Goodbye!\n";
    send(*client_socket, goodbye_message.c_str(), goodbye_message.length(), 0);

    cout << "Client from " + client_ip +" has disconnected.\n";
    // Close the socket to terminate the connection
    shutdown(*client_socket, SHUT_RDWR);  
    close(*client_socket);
}

// ---------------------------------------------------------------------
// signalHandler: Handle SIGINT and SIGTERM signals
// ---------------------------------------------------------------------

void signalHandler(int signal) 
{
    if (signal == SIGINT || signal == SIGTERM) 
    {
        cout << "\nSIGINT received - shutting down server.\n";
        abort_requested = true;

        // Close the server socket to stop accepting new connections
        if (server_socket != -1) 
            close(server_socket);

        // Close all client sockets
        {
            lock_guard<mutex> lock(sockets_mutex);
            for (int* client_socket : client_sockets) 
            {
                shutdown(*client_socket, SHUT_RDWR);
                close(*client_socket);
            }
            client_sockets.clear();  // Clear the list after closing all sockets
        }

        // Wait for all client threads to finish
        {
            lock_guard<mutex> lock(threads_mutex);
            for (auto& thread : client_threads) 
            {
                if (thread.joinable())
                    thread.join();
            }
            client_threads.clear();  // Clear the threads vector
        }

        exit(signal);  // Exit after clean shutdown
    }
}

//----------------------------------------------------------------------
// Helper-Functions
//----------------------------------------------------------------------

bool openDirectoryAndApplyLock(const string& directory_path, int lock_type, int& dir_fd) 
{
    dir_fd = open(directory_path.c_str(), O_RDONLY);
    if (dir_fd == -1) 
    {
        cerr << "Error: Unable to open directory: " << directory_path << "\n";
        return false;
    }

    if (flock(dir_fd, lock_type) == -1) 
    {
        cerr << "Error: Unable to apply lock on directory: " << directory_path << "\n";
        close(dir_fd);
        return false;
    }

    return true;
}

bool saveMessageToFile(const string &receiver, const string &sender,
                       const string &subject, const string &message_body)
{
    // Create the user's inbox directory if it doesn't exist
    string inbox_dir = mail_spool_directory + "/" + receiver + "_inbox";
    if (!filesystem::exists(inbox_dir))
    {
        error_code ec;
        if (!filesystem::create_directory(inbox_dir, ec))
        {
            cerr << "Error: Unable to create inbox directory. " << ec.message() << "\n";
            return false;
        }
    }

    // Open the inbox directory and lock it for exclusive access
    int inbox_dir_fd = open(inbox_dir.c_str(), O_RDONLY);
    if (inbox_dir_fd == -1) 
    {
        cerr << "Error: Unable to open inbox directory for user: " << receiver << ".\n";
        return false;
    }

    if (flock(inbox_dir_fd, LOCK_EX) == -1) 
    {
        cerr << "Error: Unable to lock inbox directory for user: " << receiver << ".\n";
        close(inbox_dir_fd);
        return false;
    }

    // Generate a unique file name for the message
    auto now = chrono::system_clock::now();
    auto timestamp = chrono::duration_cast<chrono::microseconds>(now.time_since_epoch()).count();
    string message_filename = inbox_dir + "/message_" + to_string(timestamp) + ".txt";

    // Open the message file for writing
    ofstream message_file(message_filename);
    if (!message_file.is_open())
    {
        cerr << "Error: Unable to create message file.\n";

        // Unlock and close the directory after saving
        flock(inbox_dir_fd, LOCK_UN);
        close(inbox_dir_fd);

        return false;
    }

    // Construct the full message
    string full_message = "From: " + sender + "\n"
                            "To: " + receiver + "\n"
                            "Subject: " + subject + "\n"
                            "Message:\n" + message_body;

    // Write the message to the file
    message_file << full_message;
    message_file.close();

    // Unlock and close the directory after saving
    flock(inbox_dir_fd, LOCK_UN);
    close(inbox_dir_fd);

    return true;
}

// Check, if the username consists of only lowercase letters and numbers and has a maximum length of 8 characters
bool isValidUsername(const string& username) 
{
    if (username.length() > 8 || username.length() == 0)
    {
        return false;  // Max 8 characters
    }
    for (char c : username) 
    {
        if (!isalnum(c) || isupper(c))
        {
            return false;  // Only a-z, 0-9, no uppercase
        }
    }
    return true;
}
