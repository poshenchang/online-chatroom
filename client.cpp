// TODO: Server can receive messages from the client.
// TODO: Server can respond to client messages.
// TODO: Client can send messages to the server.
// TODO: Client can receive responses from the server.
// TODO: User Registration
// TODO: User Login
// TODO: User Logout

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <err.h>
#include <iostream>
#include <vector>
#include <map>
#include <cstring>
#include <cctype>
#include <csignal>
#include <ctime>
using namespace std;

#define BUFFERSIZE 1024

// Function prototypes

void sendString(int socket_fd, string msg);
string receiveString(int socket_fd);

// Messages

const string welcome_msg = "Welcome to the online chatroom!\n"
                            "------------------------------------\n"
                            "You are now connected.\n"
                            "Type 'help' for a list of commands.\n"
                            "Enjoy your session!\n"
                            "------------------------------------\n";
const string cmd_prompt = "Enter command: ";
const string invalid_msg = "Invalid command. Try again.";
const string help_msg = "------------------------------------\n"
                        "Command options:\n"
                        "help               show this help message\n"
                        "register           user registration\n"
                        "login              login authentication\n"
                        "logout             user logout\n"
                        "hello/hi           say hello!\n"
                        "exit               exit server session\n"
                        "------------------------------------\n";
const string working_msg = "Utility under construction.";
const string exit_msg = "Session ended.\n"
                        "See you next time!\n";

// file descriptor for communicating with server
int socket_fd;

// Initialize socket and connect to server
static int connectServer(const char* serverIP, const unsigned short portnum){
    struct sockaddr_in serverAddr;

    // Create the socket
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(socket_fd < 0){
        cerr << "Error creating socket" << endl;
        return -1;
    }

    // Set up the server address structure
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(portnum);
    if(inet_pton(AF_INET, serverIP, &serverAddr.sin_addr) <= 0){
        cerr << serverIP << endl;
        cerr << "Invalid Address" << endl;
        close(socket_fd);
        return -1;
    }

    // Connect to the server
    if(connect(socket_fd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0){
        cerr << "Connection Failed" << endl;
        close(socket_fd);
        return -1;
    }
    cout << "Connected to server at " << serverIP << ":" << portnum << endl;

    return 0;
}

// write std::string to file descriptor
void sendString(int fd, string msg){
    ssize_t nbytes = send(fd, msg.c_str(), msg.length(), 0);
    if(nbytes == -1){
        perror("send");
    }
}

// read std::string from file descriptor
string receiveString(int fd){
    char buf[BUFFERSIZE];
    string str;
    ssize_t nbytes = recv(fd, buf, BUFFERSIZE, 0);
    if(nbytes == -1){
        perror("send");
    }
    else if(nbytes > 0){
        str.append(buf, nbytes);
    }
    while(!str.empty() && (str.back() == '\r' || str.back() == '\n')){
        str.pop_back();
    }
    return str;
}

bool usernameValid(string str){
    for(auto it = str.begin(); it != str.end(); ++it){
        if(!isdigit(*it) && !isalpha(*it)) return false;
    }
    return true;
}

bool passwordValid(string str){
    for(auto it = str.begin(); it != str.end(); ++it){
        if(!isdigit(*it) && !isalpha(*it)) return false;
    }
    return true;
}

bool isSuccess(){
    string str = receiveString(socket_fd);
    return (str == "SUCCESS");
}

// Check and convert string to positive integer
int strToInt(string str){
    for(auto it = str.begin(); it != str.end(); ++it){
        if(!isdigit(*it)) return -1;
    }
    return stoi(str);
}

// Convert std::string to lowercase
void strToLower(string& str){
    for(auto it = str.begin(); it != str.end(); ++it){
        *it = tolower(*it);
    }
}

int main(int argc, char** argv){
    if(argc != 3){
        cerr << "Usage: " << argv[0] << " [IP address] [port]" << endl;
        exit(1);
    }

    // Initialize socket and connect to server
    connectServer(argv[1], strToInt(argv[2]));

    cout << welcome_msg;
    bool exit = false;
    // 'cmd' for reading command from client; 'status' for reading return status from server
    string cmd, stat;
    string currentUser = "";
    while(!exit){
        cout << cmd_prompt;
        cin >> cmd;
        strToLower(cmd);
        if(cmd == "help"){
            cout << help_msg;
        }
        else if(cmd == "register"){
            cout << "Usernames can only contain letters (A-Z, a-z) and digits (0-9)." << endl;
            string username, password ;
            while(true){
                cout << "Enter your username: ";
                cin >> username;
                if(!usernameValid(username)) cout << "Invalid username. Try another one." << endl;
                else{
                    sendString(socket_fd, "checkuser " + username + '\n');
                    if(isSuccess()) cout << "Username already taken. Try another one." << endl;
                    else break;
                }
            }
            cout << "Passwords can only contain letters (A-Z, a-z) and digits (0-9)." << endl;
            while(true){
                cout << "Enter your password: ";
                cin >> password;
                if(!usernameValid(password)) cout << "Invalid password. Try another one." << endl;
                else break;
            }
            sendString(socket_fd, "register " + username + " " + password + '\n');
            if(isSuccess()){
                cout << "Successfully registered!" << endl;
            }
            else cout << "Register failed." << endl;
            
        }
        else if(cmd == "login"){
            if(!currentUser.empty()){
                cout << "Already logged in. To log in as a different user, please log out first." << endl;
                continue;
            }
            string username, password;
            // Enter username
            cout << "Enter your username: ";
            cin >> username;
            sendString(socket_fd, "checkuser " + username + '\n');
            if(!isSuccess()){
                cout << "Username does not exist." << endl;
                continue;
            }
            // Enter password
            cout << "Enter your password: ";
            cin >> password;
            sendString(socket_fd, "login " + username + ' ' + password + '\n');
            if(isSuccess()){
                cout << "Successfully login!" << endl;
                currentUser = username;
            }
            else cout << "Login failed." << endl;
        }
        else if(cmd == "logout"){
            if(currentUser.empty()){
                cout << "You are not currently logged in. Please log in first." << endl;
                continue;
            }
            sendString(socket_fd, "logout\n");
            if(isSuccess()){
                cout << "Successfully logout!" << endl;
                currentUser = "";
            }
            else cout << "Logout failed." << endl;
        }
        else if(cmd == "hello" || cmd == "hi"){
            if(!currentUser.empty()){
                cout << "Hello, " << currentUser << "! Welcome to the chatroom!" << endl;
            }
            else{
                cout << "Hello, guest! Welcome to the chatroom!" << endl;
            }
            
        }
        else if(cmd == "exit"){
            sendString(socket_fd, "exit\n");
            exit = true;
        }
        else{
            cout << invalid_msg << endl;
        }
    }
    cout << exit_msg;
    close(socket_fd);

    return 0;
}