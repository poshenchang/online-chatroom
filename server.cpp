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
#include <pthread.h>
#include <unistd.h>
#include <err.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <queue>
#include <map>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <csignal>
#include <ctime>
using namespace std;

#define BUFFERSIZE 1024
#define MAXCMDARG 3
#define MAXWORKERS 10

// Function prototypes

void sendString(int socket_fd, string msg);
string receiveString(int socket_fd);

// Messages and Strings

string delim = " \t\r\n";

inline void sendSuccess(int socket_fd){
    sendString(socket_fd, "SUCCESS\n");
}
inline void sendFail(int socket_fd){
    sendString(socket_fd, "FAIL\n");
}

// Client

class Client{
    public:
        string host;                // client's host
        int connect_fd;             // fd to talk with client
        string username;            // username of client connection
        string buf;                 // data sent by/to client
        size_t buf_len;             // bytes used by buf
        bool login;
        bool alive;

        Client(){}
        Client(string host, int fd);
};

Client::Client(string host, int fd){
    this->host = host;
    this->connect_fd = fd;
    this->username.clear();
    this->buf_len = 0;
    this->login = false;
    this->alive = true;
}

enum status{
    ONLINE,
    OFFLINE,
    IDLE
};

// User

class User{
    public:
        string username;
        string password;
        status stat;

        User(){}
        User(string username, string password);
};

User::User(string username, string password){
    this->username = username;
    this->password = password;
    this->stat = OFFLINE;
}

class UserDB{
    private:
        map<string, User> reg;
        map<string, vector<string> > msg;
    public:
        bool checkUser(string username);
        void userRegister(string username, string password);
        bool userLogin(string username, string password);
        void userLogout(string username);
};

bool UserDB::checkUser(string username){
    return (reg.count(username));
}

void UserDB::userRegister(string username, string password){
    reg.insert(make_pair(username, User(username, password)));
    msg.insert(make_pair(username, vector<string>()));
}

bool UserDB::userLogin(string username, string password){
    cerr << "check password " << password << endl;
    if(reg[username].password == password && reg[username].stat == OFFLINE){
        reg[username].stat = ONLINE;
        return true;
    }
    return false;
}

void UserDB::userLogout(string username){
    reg[username].stat = OFFLINE;
}

// maximum number of file descriptors
int maxfd;
// server hostname
string hostname;
// file descriptor for listening incoming requesets
int listen_fd;
// server port
unsigned short port;
// stores data of ongoing clients
map<int, Client> req;
pthread_mutex_t reqMutex = PTHREAD_MUTEX_INITIALIZER;
// stores data of registered users
UserDB userDatabase;
pthread_mutex_t userMutex = PTHREAD_MUTEX_INITIALIZER;

void signalHandler(int signo) {
    if(signo == SIGPIPE){
        pid_t pid = getpid();
        fprintf(stderr, "Process %d terminated due to SIGPIPE\n", pid);
    }
    exit(EXIT_FAILURE);
}

static int initServer(const unsigned short portnum){
    struct sockaddr_in serverAddr;
    int tmp;

    char namebuf[512];
    gethostname(namebuf, sizeof(namebuf));
    hostname = namebuf;
    port = portnum;

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(listen_fd < 0){
        cerr << "Error creating socket" << endl;
        return -1;
    }

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddr.sin_port = htons(port);
    tmp = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (void*)&tmp, sizeof(tmp));
    bind(listen_fd, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    listen(listen_fd, 1024);

    // Get file descripter table size
    maxfd = getdtablesize();
    cerr << "\nstarting server on " << hostname << ", port "<< portnum << '\n';
    return 0;
}

int acceptConnection(){
    struct sockaddr_in cliaddr;
    size_t clilen;
    int connect_fd;  // fd for a new connection with client

    clilen = sizeof(cliaddr);
    connect_fd = accept(listen_fd, (struct sockaddr*)&cliaddr, (socklen_t*)&clilen);
    if(connect_fd < 0){
        if(errno == EINTR || errno == EAGAIN) return -1;  // try again
        if(errno == ENFILE){
            cerr << "out of file descriptor table, maxfd " << maxfd << '\n';
            return -1;
        }
        cerr << "Cannot accept client connection" << endl;
    }

    // TODO: initialize new Client
    string client_host = inet_ntoa(cliaddr.sin_addr);
    req.insert(make_pair(connect_fd, Client(client_host, connect_fd)));
    cout << "new client from " << client_host << '\n';
    return connect_fd;
}

int closeConnection(int fd){
    Client cli = req[fd];
    close(cli.connect_fd);
    cerr << "closed connection with " << cli.host << endl;
    req.erase(fd);
    return 0;
}

// write std::string to file descriptor
void sendString(int socket_fd, string msg){
    ssize_t nbytes = send(socket_fd, msg.c_str(), msg.size(), 0);
    if(nbytes == -1){
        cerr << "Failed to send message" << endl;
        if(errno == EPIPE){
            req[socket_fd].alive = false;
            cerr << "Client has disconnected" << endl;
        }
    }
}

// read std::string from file descriptor
string receiveString(int socket_fd){
    char buf[BUFFERSIZE];
    string str;
    ssize_t nbytes = recv(socket_fd, buf, BUFFERSIZE, 0);
    if(nbytes == -1){
        cerr << "Failed to receive message" << endl;
    }
    else if(nbytes == 0){
        cerr << "Client terminated prematurely" << endl;
        req[socket_fd].alive = false;
    }
    else if(nbytes > 0){
        str.append(buf, nbytes);
    }
    while(!str.empty() && (str.back() == '\r' || str.back() == '\n')){
        str.pop_back();
    }
    return str;
}

// Task type
enum taskType{
    CHECKUSER,
    REGISTER,
    LOGIN,
    LOGOUT,
    EXIT
};

// Task structure
struct Task{
    int client_fd;
    taskType type;
    map<string, string> arg;
};

// Task queue
queue<Task> taskQueue;
pthread_mutex_t queueMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t taskAvailable = PTHREAD_COND_INITIALIZER;

// Worker thread function
void* worker_thread(void* arg){
    while(true){
        Task task;

        pthread_mutex_lock(&queueMutex);
        while(taskQueue.empty()){
            pthread_cond_wait(&taskAvailable, &queueMutex);
        }
        task = taskQueue.front();
        taskQueue.pop();
        pthread_mutex_unlock(&queueMutex);

        int connect_fd = task.client_fd;
        cout << "Worker " << pthread_self() << " handling client " << task.client_fd << endl;

        bool exit = false;
        while(!exit){
            string currentUser = "";

            string cmdstr = receiveString(connect_fd);
            cerr << "[command] " << cmdstr << endl;
            stringstream cmdarg(cmdstr);
            string cmd; cmdarg >> cmd;
            if(cmd == "checkuser"){
                string username;
                cmdarg >> username;
                if(userDatabase.checkUser(username)){
                    sendSuccess(connect_fd);
                }
                else sendFail(connect_fd);
            }
            else if(cmd == "register"){
                string username, password;
                cmdarg >> username >> password;
                userDatabase.userRegister(username, password);
                sendSuccess(connect_fd);
            }
            else if(cmd == "login"){
                string username, password;
                cmdarg >> username >> password;
                if(userDatabase.userLogin(username, password)){
                    currentUser = username;
                    sendSuccess(connect_fd);
                }
                else sendFail(connect_fd);
            }
            else if(cmd == "logout"){
                userDatabase.userLogout(currentUser);
                currentUser = "";
                sendSuccess(connect_fd);
            }
            else if(cmd == "exit"){
                exit = true;
            }

            // Check if client is alive
            if(!req[connect_fd].alive) exit = true;
        }
        closeConnection(connect_fd);
    }
    return nullptr;
}

int main(int argc, char** argv) {
    // Parse args
    if(argc != 2){
        cerr << "Usage: " << argv[0] << " [port]" << endl;
        exit(1);
    }

    // Signal handler
    signal(SIGPIPE, SIG_IGN);

    // Initialize server
    initServer((unsigned short) stoi(argv[1]));

    // Create worker threads
    pthread_t workers[MAXWORKERS];
    for(int i=0; i<MAXWORKERS; ++i){
        if(pthread_create(&workers[i], nullptr, worker_thread, nullptr) < 0){
            cerr << "Failed to create worker thread" << endl;
        }
    }

    while(true){
        int connect_fd = acceptConnection();
        cout << "New client connected, fd " << connect_fd << endl;

        // Add task to task queue
        Task task = {connect_fd};
        pthread_mutex_lock(&queueMutex);
        taskQueue.push(task);
        pthread_cond_signal(&taskAvailable);
        pthread_mutex_unlock(&queueMutex);
    }
    
    close(listen_fd);
    return 0;
}