// TODO: Message encryption with OpenSSL
// TODO: File tranfer
// TODO: Audio streaming

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
#include <set>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <csignal>
#include <ctime>
using namespace std;

#define BUFFERSIZE 1024
#define MAXCMDARG 3
#define MAXWORKERS 10
#define MAXWAITTIME 60

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

// maximum number of file descriptors
int maxfd;
// server hostname
string hostname;
// file descriptor for listening incoming requesets
int listen_fd;
// server port
unsigned short port;

// Client

class Client{
    public:
        string host;                // client's host
        int connect_fd;             // fd to talk with client
        string listen_port;         // listening port of client
        string username;            // username of client connection
        bool login;
        bool alive;

        Client(){}
        Client(string host, int fd, string portnum);
};

Client::Client(string host, int fd, string portnum){
    this->host = host;
    this->connect_fd = fd;
    this->listen_port = portnum;
    this->username.clear();
    this->login = false;
    this->alive = true;
}

// stores data of ongoing clients
map<int, Client> req;
pthread_rwlock_t reqRWLock = PTHREAD_RWLOCK_INITIALIZER;

enum status{
    ONLINE,
    OFFLINE,
    IDLE
};

class threadSignal{
    private:
        bool state;
        pthread_cond_t sigCond;
        pthread_mutex_t sigMutex;
    public:
        threadSignal();
        int wait(int sec);
        void signal();
};

threadSignal::threadSignal(){
    state = false;
    sigCond = PTHREAD_COND_INITIALIZER;
    sigMutex = PTHREAD_MUTEX_INITIALIZER;
}

int threadSignal::wait(int sec){
    pthread_mutex_lock(&sigMutex);
    if(!state){
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += sec;
        pthread_cond_timedwait(&sigCond, &sigMutex, &ts);
    }
    bool saveState = state;
    state = false;
    pthread_mutex_unlock(&sigMutex);
    if(!saveState) return -1;
    return 0;
}

void threadSignal::signal(){
    pthread_mutex_lock(&sigMutex);
    state = true;
    pthread_cond_signal(&sigCond);
    pthread_mutex_unlock(&sigMutex);
}

// User

class User{
    public:
        string username;
        string password;
        status stat;
        int connect_fd;
        set<string> reqSet;
        threadSignal acceptReq;

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
        pthread_rwlock_t userRWLock;
    public:
        UserDB(){
            pthread_rwlock_t userRWLock = PTHREAD_RWLOCK_INITIALIZER;
        };
        bool checkUser(string username);
        bool checkOnline(string username);
        void userRegister(string username, string password);
        bool userLogin(string username, string password, int connect_fd);
        void userLogout(string username);
        int msgRequest(string from, string to);
        int acceptRequest(string from, string to);
        int requestCount(string username);
        set<string> getRequest(string username);
        int getHostPort(string username, string& host, string& portnum);
};

bool UserDB::checkUser(string username){
    pthread_rwlock_rdlock(&userRWLock);
    bool retval = reg.count(username);
    pthread_rwlock_unlock(&userRWLock);
    return retval;
}

bool UserDB::checkOnline(string username){
    pthread_rwlock_rdlock(&userRWLock);
    bool retval =  (reg.count(username) && reg[username].stat == ONLINE);
    pthread_rwlock_unlock(&userRWLock);
    return retval;
}

void UserDB::userRegister(string username, string password){
    pthread_rwlock_wrlock(&userRWLock);
    reg.insert(make_pair(username, User(username, password)));
    pthread_rwlock_unlock(&userRWLock);
}

bool UserDB::userLogin(string username, string password, int connect_fd){
    cerr << "check password " << password << endl;
    pthread_rwlock_wrlock(&userRWLock);
    if(reg[username].password == password && reg[username].stat == OFFLINE){
        reg[username].stat = ONLINE;
        reg[username].connect_fd = connect_fd;
        pthread_rwlock_unlock(&userRWLock);
        return true;
    }
    pthread_rwlock_unlock(&userRWLock);
    return false;
}

void UserDB::userLogout(string username){
    pthread_rwlock_wrlock(&userRWLock);
    reg[username].stat = OFFLINE;
    pthread_rwlock_unlock(&userRWLock);
}

int UserDB::msgRequest(string from, string to){
    pthread_rwlock_wrlock(&userRWLock);
    reg[to].reqSet.insert(from);
    pthread_rwlock_unlock(&userRWLock);
    int retval = reg[from].acceptReq.wait(MAXWAITTIME);
    reg[to].reqSet.erase(from);
    return retval;
}

int UserDB::acceptRequest(string from, string to){
    pthread_rwlock_rdlock(&userRWLock);
    if(!reg[to].reqSet.count(from)){
        pthread_rwlock_unlock(&userRWLock);
        return -1;
    }
    pthread_rwlock_unlock(&userRWLock);
    reg[from].acceptReq.signal();
    return 0;
}

int UserDB::requestCount(string username){
    pthread_rwlock_rdlock(&userRWLock);
    int size =  reg[username].reqSet.size();
    pthread_rwlock_unlock(&userRWLock);
    return size;
}
set<string> UserDB::getRequest(string username){
    pthread_rwlock_rdlock(&userRWLock);
    set<string> Set =  reg[username].reqSet;
    pthread_rwlock_unlock(&userRWLock);
    return Set;
}

int UserDB::getHostPort(string username, string& host, string& portnum){
    pthread_rwlock_rdlock(&userRWLock);
    if(!reg.count(username)){
        pthread_rwlock_unlock(&userRWLock);
        return -1;
    }
    host = req[reg[username].connect_fd].host;
    portnum = req[reg[username].connect_fd].listen_port;
    pthread_rwlock_unlock(&userRWLock);
    return 0;
}

// stores data of registered users
UserDB userDatabase;

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

    // initialize new Client
    string client_host = inet_ntoa(cliaddr.sin_addr);
    string portnum = receiveString(connect_fd);
    pthread_rwlock_wrlock(&reqRWLock);
    req.insert(make_pair(connect_fd, Client(client_host, connect_fd, portnum)));
    pthread_rwlock_unlock(&reqRWLock);
    cout << "New client from " << client_host << ", client listening on " << portnum << endl;
    return connect_fd;
}

int closeConnection(int fd){
    pthread_rwlock_rdlock(&reqRWLock);
    Client cli = req[fd];
    pthread_rwlock_unlock(&reqRWLock);

    close(cli.connect_fd);
    cerr << "closed connection with " << cli.host << endl;

    pthread_rwlock_wrlock(&reqRWLock);
    req.erase(fd);
    pthread_rwlock_unlock(&reqRWLock);

    return 0;
}

// write std::string to file descriptor
void sendString(int socket_fd, string msg){
    ssize_t nbytes = send(socket_fd, msg.c_str(), msg.size(), 0);
    if(nbytes == -1){
        cerr << "Failed to send message" << endl;
        if(errno == EPIPE){
            pthread_rwlock_wrlock(&reqRWLock);
            req[socket_fd].alive = false;
            pthread_rwlock_unlock(&reqRWLock);
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
        pthread_rwlock_wrlock(&reqRWLock);
        req[socket_fd].alive = false;
        pthread_rwlock_unlock(&reqRWLock);
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
        string currentUser = "";
        while(!exit){
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
                if(userDatabase.userLogin(username, password, connect_fd)){
                    currentUser = username;
                    sendSuccess(connect_fd);
                }
                else sendFail(connect_fd);
            }
            else if(cmd == "logout"){
                userDatabase.userLogout(currentUser);
                currentUser.clear();
                sendSuccess(connect_fd);
            }
            else if(cmd == "connect"){
                string username;
                cmdarg >> username;
                if(!userDatabase.checkOnline(username)){
                    sendFail(connect_fd);
                    continue;
                }
                if(userDatabase.msgRequest(currentUser, username) < 0){
                    sendFail(connect_fd);
                    continue;
                }
                sendSuccess(connect_fd);
                // send client IP and portnum
                string host, portnum;
                userDatabase.getHostPort(username, host, portnum);
                sendString(connect_fd, host + '\n' + portnum + '\n');
            }
            else if(cmd == "accept"){
                string username;
                cmdarg >> username;
                if(userDatabase.acceptRequest(username, currentUser) < 0){
                    sendFail(connect_fd);
                    continue;
                }
                sendSuccess(connect_fd);
            }
            else if(cmd == "msgNum"){
                if(currentUser.empty()){
                    sendString(connect_fd, "0\n");
                }
                else{
                    int reqNum = userDatabase.requestCount(currentUser);
                    sendString(connect_fd, to_string(reqNum) + '\n');
                }
            }
            else if(cmd == "msgReq"){
                if(currentUser.empty()){
                    sendString(connect_fd, "0\n");
                }
                else{
                    set<string> reqSet = userDatabase.getRequest(currentUser);
                    sendString(connect_fd, to_string(reqSet.size()) + '\n');
                    for(auto it = reqSet.begin(); it != reqSet.end(); ++it){
                        sendString(connect_fd, *it + '\n');
                    }
                }
            }
            else if(cmd == "exit"){
                exit = true;
            }

            // Check if client is alive
            pthread_rwlock_rdlock(&reqRWLock);
            if(!req[connect_fd].alive) exit = true;
            pthread_rwlock_unlock(&reqRWLock);
        }
        if(!currentUser.empty()){
            userDatabase.userLogout(currentUser);
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