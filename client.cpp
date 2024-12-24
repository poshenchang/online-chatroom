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
#include <fstream>
#include <sstream>
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
                        "file               send/receive files\n"
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

// P2P connection

pthread_t tid_send, tid_recv;

struct P2P_struct{
    int fd;
    SSL* ssl;
};

int initP2P(string type, string remoteHost, string remotePort, P2P_struct &P2PInfo){
    int msg_fd;
    SSL* client_ssl;
    if(type == "connect"){
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
    else if(type == "accept"){
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
    else return -1;

    P2PInfo.fd = msg_fd;
    P2PInfo.ssl = client_ssl;
    return 0;
}

void closeP2P(P2P_struct &P2PInfo){
    SSL_shutdown(P2PInfo.ssl);
    SSL_free(P2PInfo.ssl);
    close(P2PInfo.fd);
}

// Direct mode messaging

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

static int directMessage(string username, string type, string remoteHost, string remotePort){
    P2P_struct P2PInfo;
    if(initP2P(type, remoteHost, remotePort, P2PInfo) < 0){
        cerr << "Failed to initialize P2P connection" << endl;
    }
    int msg_fd = P2PInfo.fd;
    SSL* client_ssl = P2PInfo.ssl;

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
    closeP2P(P2PInfo);
    pthread_join(tid_send, NULL);
    delete args;
    cout << "------------------------------------" << endl;
    return 0;
}

// File transfer

void sendFile(SSL *ssl, string filename, ifstream& file) {
    // Send the filename to the server first (optional, if needed)
    size_t filename_len = filename.size();
    SSL_write(ssl, &filename_len, sizeof(filename_len));  // Send filename length
    SSL_write(ssl, filename.c_str(), filename_len);       // Send filename

    // Read and send the file in chunks
    const size_t buffer_size = 1024;  // Buffer size to read the file
    char buffer[buffer_size];
    while (file.read(buffer, buffer_size) || file.gcount() > 0) {
        size_t bytes_read = file.gcount();
        // Send size of the data to be sent
        if(SSL_write(ssl, &bytes_read, sizeof(bytes_read)) <= 0) return;
        // Send the data
        if(SSL_write(ssl, buffer, bytes_read) <= 0) return;
    }

    // Indicate end of file transfer
    size_t end_marker = 0;
    SSL_write(ssl, &end_marker, sizeof(end_marker));

    cout << "File " << filename << " sent successfully!" << endl;
}

void receiveFile(SSL *ssl) {
    // Receive the pathname first
    size_t pathname_len;
    SSL_read(ssl, &pathname_len, sizeof(pathname_len));  // Get pathname length

    char *pathname = new char[pathname_len + 1];
    SSL_read(ssl, pathname, pathname_len);  // Get pathname
    pathname[pathname_len] = '\0';  // Null-terminate the pathname

    char* filename = pathname;  // Extract filename
    for(int i=pathname_len-1; i>=0; i--){
        if(pathname[i] == '/'){
            filename = pathname + i + 1;
        }
    }

    // Open a file to write the received data
    if (ifstream(filename)){
        cerr << "File " << filename << " already exists" << endl;
        return;
    }
    ofstream file(filename, ios::binary);
    if (!file.is_open()) {
        cerr << "Error opening file for writing " << filename << endl;
        delete[] filename;
        return;
    }

    cout << "Receiving file " << filename << " ..." << endl;

    // Receive the file in chunks
    size_t bytes_to_read;
    char buffer[1024];
    while (true) {
        SSL_read(ssl, &bytes_to_read, sizeof(bytes_to_read));  // Get the number of bytes to read
        if (bytes_to_read == 0) break;  // End of file transfer

        SSL_read(ssl, buffer, bytes_to_read);  // Receive the data
        file.write(buffer, bytes_to_read);     // Write the data to the file
    }

    cout << "File " << filename << " received successfully!" << endl;

    delete[] pathname;
    file.close();
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
            sendString("reqNum\n");
            string buf = receiveLine();
            int numReq = stoi(buf);
            if(numReq > 0){
                cout << "[Notification] You have " << numReq << " pending requests. Type 'message'/'file'/'audio' to see respective requests.\n";
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
            sendString("reqSet\n");
            set<string> msgSet;
            string buf = receiveLine();
            int numReq = stoi(buf);
            for(int i=0; i<numReq; i++){
                buf = receiveLine();
                stringstream ss; ss << buf;
                string username; int type;
                ss >> username >> type;
                if(type == 0) msgSet.insert(username);
            }
            if(msgSet.size() > 0){
                cout << "Pending message requests from:" << endl;
                for(auto username: msgSet){
                    cout << "* " << username << endl;
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
            if(msgSet.count(username)){
                // accept message
                sendString("accept " + username + '\n');
                if(!isSuccess()){
                    cout << "Message request from " << username << " expired." << endl;
                }
                string remoteHost, remotePort;
                directMessage(username, "accept", remoteHost, remotePort);
            }
            else{
                // Check if user exists
                sendString("checkuser " + username + '\n');
                if(!isSuccess()){
                    cout << "User does not exist." << endl;
                    continue;
                }
                // Send message request
                sendString("connect " + username + " 0\n");
                cout << "Connecting to " << username << ", request pending..." << endl;
                if(!isSuccess()){
                    cout << "Request failed. User offline or request timeout." << endl;
                    continue;
                }
                // get client IP and portnum
                string remoteHost = receiveLine();
                string remotePort = receiveLine();
                directMessage(username, "connect", remoteHost, remotePort);
            }            
        }
        else if(cmd == "file"){
            // Check if logged in
            if(currentUser.empty()){
                cout << "You are not currently logged in. Please log in first." << endl;
                continue;
            }
            // get pending file transfer requests
            sendString("reqSet\n");
            set<string> fileSet;
            string buf = receiveLine();
            int numReq = stoi(buf);
            for(int i=0; i<numReq; i++){
                buf = receiveLine();
                stringstream ss; ss << buf;
                string username; int type;
                ss >> username >> type;
                if(type == 1) fileSet.insert(username);
            }
            string type;
            if(fileSet.size() > 0){
                cout << "Pending file transfer requests from:" << endl;
                for(auto username: fileSet){
                    cout << "* " << username << endl;
                }
                cout << "Would you like to send a file or receive a file?\n"
                        "Enter 'S' to send or 'R' to receive: ";
                cin >> type;
            }
            else type = "S";

            if(type == "S"){
                string username;
                cout << "Who do you want to send files to? Enter username: ";
                cin >> username;
                // User cannot send file to themselves
                if(username == currentUser){
                    cout << "Choose a user other than yourself to send files to." << endl;
                    continue;
                }
                // Check if user exists
                sendString("checkuser " + username + '\n');
                if(!isSuccess()){
                    cout << "User does not exist." << endl;
                    continue;
                }
                // Select file
                string filename;
                cout << "Select a file to transfer (enter pathname): ";
                cin >> filename;
                ifstream file(filename, ios::binary);
                if (!file.is_open()) {
                    cerr << "Error opening file " << filename << endl;
                    continue;
                }
                // Send file transfer request
                sendString("connect " + username + " 1\n");
                cout << "File transfer request to " << username << " pending..." << endl;
                if(!isSuccess()){
                    cout << "Request failed. User offline or request timeout." << endl;
                    continue;
                }
                // get client IP and portnum
                string remoteHost = receiveLine();
                string remotePort = receiveLine();
                P2P_struct P2PInfo;
                initP2P("connect", remoteHost, remotePort, P2PInfo);
                sendFile(P2PInfo.ssl, filename, file);
                file.close();
            }
            else if(type == "R"){
                string username;
                // Check if user is in pending requests
                while(true){
                    cout << "Who do you want to receive files from? Enter username: ";
                    cin >> username;
                    if(!fileSet.count(username)){
                        cout << "No pending file transfer requests from " << username << endl;
                    }
                    else break;
                }
                // accept file
                sendString("accept " + username + '\n');
                if(!isSuccess()){
                    cout << "File transfer request from " << username << " expired." << endl;
                }
                // get client IP and portnum
                P2P_struct P2PInfo;
                initP2P("accept", "", "", P2PInfo);
                receiveFile(P2PInfo.ssl);
            }
            else{
                cout << "Invalid argument. " << endl;
                continue;
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