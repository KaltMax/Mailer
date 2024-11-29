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
#include <termios.h>
// C++
#include <iostream>
#include <string>

using namespace std;

//----------------------------------------------------------------------
// Constants
//----------------------------------------------------------------------

const unsigned int BUFFER_SIZE = 65536;
const size_t MAX_MESSAGE_SIZE = 65536;

//----------------------------------------------------------------------
// Function prototypes
//----------------------------------------------------------------------

int serverCommunication(int* client_socket);
void handleSend(int* client_socket);
void handleList(int* client_socket);
void handleLogin(int* client_socket);
void handleRead(int* client_socket);
void handleDel(int* client_socket);
void handleQuit(int* client_socket);
bool sendMessageToServer(int* client_socket, const string &message);
bool validateUsername(const string &username);
bool confirmQuit();
int getch();
const string getpass();

//----------------------------------------------------------------------
//  M A I N
//----------------------------------------------------------------------

int main(int argc, char **argv)
{
    int return_code = EX_OK; // EX_OK is defined in sysexits.h
    int client_socket;
    struct sockaddr_in address;
    int status = -1;

    // Validate arguments
    if (argc < 3) 
    {
        cerr << "Usage: " << argv[0] << " <ip> <port>\n";
        return(EX_USAGE);
    }

    // Create socket descriptor
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) 
    {
        cerr << "Error getting socket descriptor: " << strerror(errno) << " (" << errno << ")\n";
        return(EX_CANTCREAT);
    }

    // Initialise address structure with server address and port
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(stoi(argv[2]));  // Use provided port from argv[2]
    
    if (inet_aton(argv[1], &address.sin_addr) == 0)  // Convert IP from argv[1]
    {
        cerr << "Invalid IP address format.\n";
        return(EX_USAGE);
    }

    // Create a connection to the server
    status = connect(client_socket, (struct sockaddr*)&address, sizeof(address));
    if (status == -1) 
    {
        cerr << "Error connecting to server: " << strerror(errno) << " (" << errno << ")\n";
        return(EX_UNAVAILABLE);
    }
    cout << "Connected to server " << inet_ntoa(address.sin_addr) << ".\n";

    // Receive server welcome message
    char buffer[BUFFER_SIZE];
    int size = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    if (size > 0) 
    {
        buffer[size] = '\0'; // Null-terminate buffer
        cout << buffer;

        // Check if client is blocked
        if(strcmp(buffer, "ERR\n") == 0)
        {
            cerr << "You are blocked! Try again later!\n";
            return(EX_UNAVAILABLE);
        }
    }
    else 
    {
        cerr << "Error receiving data from server: " << strerror(errno) << " (" << errno << ")\n";
        return(EX_OSERR);
    }

    // Enter main communication loop
    return_code = serverCommunication(&client_socket);

    // Shutdown and close the socket descriptor
    if (client_socket != -1) 
    {
        status = shutdown(client_socket, SHUT_RDWR);
        if (status == -1) 
        {
            cerr << "Error shutting down socket: " << strerror(errno) << " (" << errno << ")\n";
            return_code = EX_OSERR;
        }
        status = close(client_socket);
        if (status == -1) 
        {
            cerr << "Error closing socket: " << strerror(errno) << " (" << errno << ")" << "\n";
            return_code = EX_OSERR;
        }
    }

    return return_code;
}

//----------------------------------------------------------------------
// Functions for login and communicating with the server
//----------------------------------------------------------------------

void handleLogin(int* client_socket) 
{
    string username;
    string password;

    while(true) {
        // Prompt for username
        cout << "Enter your UserId: ";
        getline(cin, username);
        if (validateUsername(username))
        {
            break;
        }
        cerr << "Invalid username. Only lowercase letters and digits, max 8 characters.\n";
    }
    
    while(true)
    {
        // Prompt for password
        cout << "Enter your Password: ";
        password = getpass();
        if (!password.empty())
        {
            break;
        }
        cerr << "Password cannot be empty.\n";
    }

    // Send username and password to server
    string credentials = "LOGIN\n" + username + "\n" + password + "\n";
    sendMessageToServer(client_socket, credentials);
}

int serverCommunication(int* client_socket)
{
    string message;
    bool quit = false;

    // Main communication loop
    do 
    {
        cout << ">> ";
        getline(cin, message);

        // Command handling using if and else if statements
        if (message == "LOGIN") 
        {
            handleLogin(client_socket);
        }
        else if (message == "SEND") 
        {
            handleSend(client_socket);
        }
        else if (message == "LIST") 
        {
            handleList(client_socket);
        }
        else if (message == "READ") 
        {
            handleRead(client_socket);
        }
        else if (message == "DEL") 
        {
            handleDel(client_socket);
        }
        else if (message == "QUIT") 
        {
            if (confirmQuit()) 
            {
                handleQuit(client_socket);
                quit = true;
            }
        }
        else 
        {
            cerr << "Unknown command. Please use SEND, LIST, READ, DEL, or QUIT.\n";
        }

    } while (!quit);

    return 0;
}

//----------------------------------------------------------------------
// Functions for handling the client commands
//----------------------------------------------------------------------

void handleSend(int* client_socket) 
{
    string receiver, subject, line, message;

    while(true)
    {
        cout << "Enter Receiver: ";
        getline(cin, receiver);
        if (validateUsername(receiver))
        {
          break;  
        } 
        cerr << "Invalid receiver username. Only lowercase letters and digits, max 8 characters.\n";
    }

    // Validate subject Length
    while(true)
    {
        cout << "Enter Subject (max 80 chars): ";
        getline(cin, subject);
        if (subject.length() <= 80 && !subject.empty())
        {
            break;
        }
        cerr << "Subject exceeds maximum length of 80 characters or is empty.\n";
    }

    while(true)
    {
        cout << "Enter Message (end with a dot '.' on a new line):\n";
        while (getline(cin, line)) 
        {
            if (line == ".") break;  // End message input
            message += line + "\n";
        }
        if (message.length() > 0)
        {
            break;
        }
        cerr << "Message cannot be empty.\n";
    }

    // Send the formatted SEND command to the server
    string full_message = "SEND\n" + receiver + "\n" + subject + "\n" + message + ".\n";
    sendMessageToServer(client_socket, full_message);
}

void handleList(int* client_socket) 
{
    // Send the LIST command to the server
    string full_message = "LIST\n";
    sendMessageToServer(client_socket, full_message);
}

void handleRead(int* client_socket) 
{
    string message_number;

    cout << "Enter Message Number: ";
    getline(cin, message_number);

    // Send the READ command to the server
    string full_message = "READ\n" + message_number + "\n";
    sendMessageToServer(client_socket, full_message);
}

void handleDel(int* client_socket) 
{
    string message_number;

    cout << "Enter Message Number: ";
    getline(cin, message_number);

    // Send the DEL command to the server
    string full_message = "DEL\n" + message_number + "\n";
    sendMessageToServer(client_socket, full_message);
}

void handleQuit(int* client_socket) 
{
    // Send the QUIT command to the server
    sendMessageToServer(client_socket, "QUIT\n");
}

bool sendMessageToServer(int* client_socket, const string &message) 
{
    char buffer[BUFFER_SIZE];

    if (message.length() > MAX_MESSAGE_SIZE) 
    {
    cerr << "Error: Message exceeds the maximum allowed size of " 
            << MAX_MESSAGE_SIZE << " bytes.\n";
    return false;
    }

    int status = send(*client_socket, message.c_str(), message.length(), 0);
    if (status == -1) 
    {
        cerr << "Error sending data to server: " << strerror(errno) << " (" << errno << ")\n";
        return false;
    }

    // Receive feedback from server
    int size = recv(*client_socket, buffer, BUFFER_SIZE-1, 0);
    if (size == -1) 
    {
        cerr << "Error receiving data from server: " << strerror(errno) << " (" << errno << ")\n";
        return false;
    }
    else if (size == 0) 
    {
        // Server closed the connection
        cout << "Server has terminated the connection. Exiting...\n";
        close(*client_socket);  
        exit(0);
    }
    else 
    {
        // Null-terminate the buffer and print the server response
        buffer[size] = '\0';
        cout << "<< " << buffer << "\n";
        if(strcmp(buffer, "OK\n") == 0) 
        {
            return true;
        }
        
        return false; 
    }
}

//----------------------------------------------------------------------
// Helper Functions
//----------------------------------------------------------------------

bool validateUsername(const string &username) 
{
    if (username.empty())
    {
        return false;
    }
    if (username.length() > 8)
    {
        return false;
    }
    for (char c : username) {
        if (!isalnum(c) || isupper(c))
        {
            return false;
        }
    }
    return true;
}

bool confirmQuit() 
{
    cout << "Are you sure you want to quit? (y/n): ";
    string confirmation;
    getline(cin, confirmation);
    return confirmation == "y" || confirmation == "Y";
}

int getch()
{
    int ch;

    struct termios t_old, t_new;

    tcgetattr(STDIN_FILENO, &t_old);
    
    t_new = t_old;

    t_new.c_lflag &= ~(ICANON | ECHO);
    
    tcsetattr(STDIN_FILENO, TCSANOW, &t_new);

    ch = getchar();

    tcsetattr(STDIN_FILENO, TCSANOW, &t_old);

    return ch;
}

const string getpass()
{
    int show_asterisk = 1;

    const char BACKSPACE = 127;
    const char RETURN = 10;

    unsigned char ch = 0;
    string password;

    while ((ch = getch()) != RETURN)
    {
        if (ch == BACKSPACE)
        {
            if (password.length() != 0)
            {
                if (show_asterisk)
                {
                    cout << "\b \b"; // backslash: \b
                }
                password.resize(password.length() - 1);
            }
        }
        else
        {
            password += ch;
            if (show_asterisk)
            {
                cout << '*';
            }
        }
    }
    cout << "\n";
    return password;
}