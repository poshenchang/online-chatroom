// TODO: File tranfer
// TODO: Audio streaming

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>
#include <err.h>
#include <iostream>
#include <vector>
#include <map>
#include <set>
#include <cstdio>
#include <cstring>
#include <cctype>
#include <csignal>
#include <ctime>
#include <climits>
#include <atomic>
using namespace std;

#define BUFFERSIZE 1024

// Function prototypes

void sendString(string msg);
string receiveString();

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
                        "message/msg        chat with other users\n"
                        "exit               exit server session\n"
                        "------------------------------------\n";
const string working_msg = "Utility under construction.";
const string exit_msg = "Session ended.\n"
                        "See you next time!\n";

// file descriptor for communicating with server
int socket_fd;
FILE* server_fp;
unsigned short listen_port;
int listen_fd;

// SIGTSTP flag

atomic<bool> interrupted(false);

void signalHandler(int signo){
    if(signo == SIGTSTP){
        interrupted.store(true);
    }
}

// OpenSSL

SSL_CTX* server_ctx;
SSL_CTX* client_ctx;
SSL* server_ssl;
const char* private_key_path = "./key.pem";
const char* certificate_path = "./cert.pem";

void init_openssl(){
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    SSL_library_init();
}

SSL_CTX* create_context(string type) {
    SSL_CTX *ctx;
    if(type == "server")
        ctx = SSL_CTX_new(TLS_server_method());
    else if(type == "client")
        ctx = SSL_CTX_new(TLS_client_method());
    else return NULL;

    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(server_ctx, certificate_path, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(server_ctx, private_key_path, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void ssl_print_error(int err){
    if(err == SSL_ERROR_ZERO_RETURN){
        cerr << "SSL_ERROR_ZERO_RETURN" << endl;
    }
    else if(err == SSL_ERROR_WANT_READ){
        cerr << "SSL_ERROR_WANT_READ" << endl;
    }
    else if(err == SSL_ERROR_WANT_WRITE){
        cerr << "SSL_ERROR_WANT_WRITE" << endl;
    }
    else if(err == SSL_ERROR_SYSCALL){
        cerr << "SSL_ERROR_SYSCALL" << endl;
    }
    else if(err == SSL_ERROR_SSL){
        cerr << "SSL_ERROR_SSL" << endl;
    }
}

// Initialize socket and connect to server
static int connectServer(const char* serverIP, const unsigned short portnum){
    struct sockaddr_in serverAddr;

    // Create the socket
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(socket_fd < 0){
        cerr << "Error creating socket" << endl;
        exit(-1);
    }

    // Set up the server address structure
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(portnum);
    if(inet_pton(AF_INET, serverIP, &serverAddr.sin_addr) <= 0){
        cerr << serverIP << endl;
        cerr << "Invalid Address" << endl;
        close(socket_fd);
        exit(-1);
    }

    // Connect to the server
    if(connect(socket_fd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0){
        cerr << "Connection Failed" << endl;
        close(socket_fd);
        exit(-1);
    }

    // Setup OpenSSL
    init_openssl();
    client_ctx = create_context("client");
    server_ctx = create_context("server");
    configure_context(server_ctx);
    server_ssl = SSL_new(client_ctx);
    SSL_set_fd(server_ssl, socket_fd);
    if (SSL_connect(server_ssl) != 1) {
        cerr << "SSL connect failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(-1);
    }
    // SSL_write(server_ssl, "test message\n", 13);

    cout << "Connected to server at " << serverIP << ":" << portnum << endl;

    return 0;
}

static int setupListen(){
    struct sockaddr_in clientAddr;
    int tmp;

    char namebuf[512];
    gethostname(namebuf, sizeof(namebuf));

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(listen_fd < 0){
        cerr << "Error creating socket" << endl;
        exit(-1);
    }

    memset(&clientAddr, 0, sizeof(clientAddr));
    clientAddr.sin_family = AF_INET;
    clientAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    clientAddr.sin_port = htons(0);
    tmp = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (void*)&tmp, sizeof(tmp));
    bind(listen_fd, (struct sockaddr*)&clientAddr, sizeof(clientAddr));
    listen(listen_fd, 1024);

    // tell server the listening port
    socklen_t len = sizeof(clientAddr);
    getsockname(listen_fd, (struct sockaddr*)&clientAddr, &len);
    listen_port = ntohs(clientAddr.sin_port);
    sendString(to_string(listen_port) + '\n');

    cerr << "listening on port "<< listen_port << endl;
    return 0;
}

void cleanupClient(){
    SSL_shutdown(server_ssl);
    SSL_free(server_ssl);
    close(socket_fd);
    SSL_CTX_free(client_ctx);
    SSL_CTX_free(server_ctx);
    EVP_cleanup();
}

// direct modes messaging

pthread_t tid_send, tid_recv;

struct msg_struct{
    SSL* ssl;
    string username;
};

void* sendMessage(void* args){
    struct msg_struct* msg_args = (struct msg_struct*)args;
    SSL* client_ssl = msg_args->ssl;
    string username = msg_args->username;

    string message;
    while (true) {
        cout << "> ";
        getline(cin, message);
        // exit when receive SIGTSTP
        if(interrupted.load()){
            cout << "\nCtrl+Z pressed. Leaving chatroom..." << endl;
            interrupted.store(false);
            break;
        }
        if (SSL_write(client_ssl, message.c_str(), message.size()) <= 0) break;
    }
    pthread_cancel(tid_recv);
    return nullptr;
}

void* receiveMessage(void* args){
    struct msg_struct* msg_args = (struct msg_struct*)args;
    SSL* client_ssl = msg_args->ssl;
    string username = msg_args->username;

    char buf[1024];
    while(true){
        ssize_t nbytes = SSL_read(client_ssl, buf, sizeof(buf)-1);
        // exit when remote disconnects
        if(nbytes <= 0){
            cout << "User " << username << " has left." << endl;
            break;
        }
        buf[nbytes] = '\0';
        cout << '\r' << username << ": " << buf << "\n> " << flush; // Redisplay prompt
    }
    pthread_cancel(tid_send);
    return nullptr;
}

static int directMessage(string username, bool init, string remoteHost, string remotePort){
    int msg_fd;
    SSL* client_ssl;
    if(init){
        struct sockaddr_in cliAddr;
        unsigned short portnum = stoi(remotePort);
        // Create the socket
        msg_fd = socket(AF_INET, SOCK_STREAM, 0);
        if(msg_fd < 0){
            cerr << "Error creating socket" << endl;
            return -1;
        }
        // Setup the client address structure
        memset(&cliAddr, 0, sizeof(cliAddr));
        cliAddr.sin_family = AF_INET;
        cliAddr.sin_port = htons(portnum);
        if(inet_pton(AF_INET, remoteHost.c_str(), &cliAddr.sin_addr) <= 0){
            cerr << remoteHost << endl;
            cerr << "Invalid Address" << endl;
            close(msg_fd);
            return -1;
        }
        // Connect to the remote client
        if(connect(msg_fd, (struct sockaddr*)&cliAddr, sizeof(cliAddr)) < 0){
            cerr << "Connection Failed" << endl;
            close(msg_fd);
            return -1;
        }
        // Setup OpenSSL
        client_ssl = SSL_new(client_ctx);
        SSL_set_fd(client_ssl, msg_fd);
        if(SSL_connect(client_ssl) <= 0){
            ERR_print_errors_fp(stderr);
        }
    }
    else{
        struct sockaddr_in cliAddr;
        size_t clilen;

        clilen = sizeof(cliAddr);
        msg_fd = accept(listen_fd, (struct sockaddr*)&cliAddr, (socklen_t*)&clilen);
        if(msg_fd < 0){
            if(errno == EINTR || errno == EAGAIN) return -1;  // try again
            cerr << "Cannot accept client connection" << endl;
        }
        // Setup OpenSSL
        client_ssl = SSL_new(server_ctx);
        SSL_set_fd(client_ssl, msg_fd);
        if(SSL_accept(client_ssl) <= 0){
            ERR_print_errors_fp(stderr);
        }
    }

    // clear cin buffer
    string _str; getline(cin, _str);
    cout << "Established connection with " << username << "." << endl;
    cout << "Press Ctrl+Z to exit the chatroom." << endl;
    cout << "Enjoy your time!\n"
            "------------------------------------" << endl;
    
    msg_struct *args = new msg_struct;
    args->ssl = client_ssl;
    args->username = username;
    pthread_create(&tid_send, NULL, sendMessage, args);
    pthread_create(&tid_recv, NULL, receiveMessage, args);
    
    // cleanup
    pthread_join(tid_recv, NULL);
    SSL_shutdown(client_ssl);
    SSL_free(client_ssl);
    close(msg_fd);
    pthread_join(tid_send, NULL);
    delete args;
    cout << "------------------------------------" << endl;
    return 0;
}

// read std::string from server_ssl
string receiveLine() {
    string line;
    char buffer[1];
    while (true) {
        int bytes_read = SSL_read(server_ssl, buffer, 1);
        if (bytes_read > 0) {
            // Append the character to the line
            line += buffer[0];
            // Stop if a newline is found
            if (buffer[0] == '\n') {
                line.pop_back();
                break;
            }
        } else {
            int error = SSL_get_error(server_ssl, bytes_read);
            if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
                continue; // Retry on non-blocking mode
            } else {
                throw runtime_error("SSL_read error or connection closed");
            }
        }
    }
    return line;
}

// write std::string to file descriptor
void sendString(string msg){
    ssize_t ret = SSL_write(server_ssl, msg.c_str(), msg.length());
    if(ret <= 0){
        int err = SSL_get_error(server_ssl, ret);
        ssl_print_error(err);
    }
}

// read std::string from file descriptor
string receiveString(){
    char buf[BUFFERSIZE];
    string str;
    ssize_t nbytes = SSL_read(server_ssl, buf, BUFFERSIZE);
    if(nbytes <= 0){
        ERR_print_errors_fp(stderr);
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
    string str = receiveString();
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
        cerr << "Usage: " << argv[0] << " [server IP address] [server port]" << endl;
        exit(1);
    }

    // Initialize socket and connect to server
    connectServer(argv[1], strToInt(argv[2]));
    setupListen();
    server_fp = fdopen(socket_fd, "a+");
    setbuf(server_fp, NULL);

    // Initialize signal handler
    struct sigaction sa;
    sa.sa_handler = signalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTSTP, &sa, NULL);

    cout << welcome_msg;
    bool exit = false;
    // 'cmd' for reading command from client; 'stat' for reading return status from server
    string cmd, stat;
    string currentUser = "";
    while(!exit){
        // check for pending message requests
        if(!currentUser.empty()){
            sendString("msgNum\n");
            string buf = receiveLine();
            int numReq = stoi(buf);
            if(numReq > 0){
                cout << "[Notification] You have " << numReq << " pending message requests. Type 'message' to enter chatroom.\n";
            }
        }

        cout << cmd_prompt;
        while(!(cin >> cmd)){
            cin.clear();
        }
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
                    sendString("checkuser " + username + '\n');
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
            sendString("register " + username + " " + password + '\n');
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
            sendString("checkuser " + username + '\n');
            if(!isSuccess()){
                cout << "User does not exist." << endl;
                continue;
            }
            // Enter password
            cout << "Enter your password: ";
            cin >> password;
            sendString("login " + username + ' ' + password + '\n');
            if(isSuccess()){
                cout << "Successfully login!" << endl;
                currentUser = username;
            }
            else cout << "Login failed. Wrong password or user already logged in at another session." << endl;
        }
        else if(cmd == "logout"){
            // Check if logged in
            if(currentUser.empty()){
                cout << "You are not currently logged in. Please log in first." << endl;
                continue;
            }
            sendString("logout\n");
            if(isSuccess()){
                cout << "Successfully logout!" << endl;
                currentUser = "";
            }
            else cout << "Logout failed." << endl;
        }
        else if(cmd == "message" || cmd == "msg"){
            // Check if logged in
            if(currentUser.empty()){
                cout << "You are not currently logged in. Please log in first." << endl;
                continue;
            }
            // get pending message requests
            sendString("msgReq\n");
            set<string> reqSet;
            string buf = receiveLine();
            int numReq = stoi(buf);
            if(numReq > 0){
                cout << "Pending message requests from:" << endl;
                for(int i=0; i<numReq; i++){
                    buf = receiveLine();
                    reqSet.insert(buf);
                    cout << "* " << buf << endl;
                }
            }

            string username;
            cout << "Who do you want to message? Enter username: ";
            cin >> username;
            // User cannot message themselves
            if(username == currentUser){
                cout << "Choose a user other than yourself to message." << endl;
                continue;
            }
            // Check if user is in pending requests
            if(reqSet.count(username)){
                // accept message
                sendString("accept " + username + '\n');
                if(!isSuccess()){
                    cout << "Message request from " << username << " expired." << endl;
                }
                string remoteHost, remotePort;
                directMessage(username, false, remoteHost, remotePort);
            }
            else{
                // Check if user exists
                sendString("checkuser " + username + '\n');
                if(!isSuccess()){
                    cout << "User does not exist." << endl;
                    continue;
                }
                // Send message request
                sendString("connect " + username + '\n');
                cout << "Connecting to " << username << ", request pending..." << endl;
                if(!isSuccess()){
                    cout << "Request failed. User offline or request timeout." << endl;
                    continue;
                }
                // get client IP and portnum
                string remoteHost = receiveLine();
                string remotePort = receiveLine();
                directMessage(username, true, remoteHost, remotePort);
            }            
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
            sendString("exit\n");
            exit = true;
        }
        else{
            cout << invalid_msg << endl;
        }
    }
    cout << exit_msg;
    cleanupClient();

    return 0;
}