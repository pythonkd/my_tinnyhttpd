/* J. David's webserver */
/* This is a simple webserver.
 * Created November 1999 by J. David Blackstone.
 * CSE 4344 (Network concepts), Prof. Zeigler
 * University of Texas at Arlington
 */
/* This program compiles for Sparc Solaris 2.6.
 * To compile for Linux:
 *  1) Comment out the #include <pthread.h> line.
 *  2) Comment out the line that defines the variable newthread.
 *  3) Comment out the two lines that run pthread_create().
 *  4) Uncomment the line that runs accept_request().
 *  5) Remove -lsocket from the Makefile.
 */
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <strings.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdint.h>

#define ISspace(x) isspace((int)(x))

#define SERVER_STRING "Server: jdbhttpd/0.1.0\r\n"
#define STDIN   0
#define STDOUT  1
#define STDERR  2

void accept_request(void *);
void bad_request(int);
void cat(int, FILE *);
void cannot_execute(int);
void error_die(const char *);
void execute_cgi(int, const char *, const char *, const char *);
int get_line(int, char *, int);
void headers(int, const char *);
void not_found(int);
void serve_file(int, const char *);
int startup(u_short *);
void unimplemented(int);

/**********************************************************************/
/* A request has caused a call to accept() on the server port to
 * return.  Process the request appropriately.
 * Parameters: the socket connected to the client */
/**********************************************************************/
void accept_request(void *arg)
{
	//pthread_create传过来的参数(void *)(intptr_t)client_sock
    int client = (intptr_t)arg;
    char buf[1024];
	/*size_t是标准C库中定义的，应为unsigned int，在64位系统中为 
	long unsigned int。数据类型"socklen_t"和int应该具有相同的长度，
	否则就会破坏 BSD套接字层的填充。*/
    size_t numchars;
    char method[255];
    char url[255];
    char path[512];
    size_t i, j;
	/*在使用这个结构体和方法时，需要引入：<sys/types.h>、<sys/stat.h>
	struct stat这个结构体是用来描述一个linux系统文件系统中的文件属性
	的结构。有两种方法获得一个文件的属性
	
	第一种是通过路径有两个函数可以得到
	int stat(const char *path, struct stat *struct_stat);
	int lstat(const char *path,struct stat *struct_stat);
	两个函数的第一个参数都是文件的路径，第二个参数是struct stat的指针。
	返回值为0，表示成功执行。执行失败是，error被自动设置对应值。
	这两个方法区别在于stat没有处理字符链接(软链接）的能力，
	如果一个文件是符号链接，stat会直接返回它所指向的文件的属性；
	而lstat返回的就是这个符号链接的内容。
	（符号连接就是软连接，软链接的内容就是一个字符串。这个字符串就是它所链接的文件的绝对路径或者相对路径）
	
	第二种通过文件描述符
	int fstat(int fdp, struct stat *struct_stat);　　
	*通过文件描述符获取文件对应的属性。fdp为文件描述符
	*/
	
    struct stat st;
    int cgi = 0;      /* becomes true if server decides this is a CGI
                       * program */
    char *query_string = NULL;

    numchars = get_line(client, buf, sizeof(buf));
    i = 0; j = 0;
    while (!ISspace(buf[i]) && (i < sizeof(method) - 1))
    {
        method[i] = buf[i];
        i++;
    }
    j=i;
    method[i] = '\0';
	//#include <strings.h> int strcasecmp(cost char*s1,const char* s2);
	//若参数s1和s2字符串相等则返回0。s1大于s2则返回大于0 的值，s1 小于s2 则返回小于0的值。
    if (strcasecmp(method, "GET") && strcasecmp(method, "POST"))
    {
        unimplemented(client);
        return;
    }
	//get提交，提交的信息都显示在地址栏中。get提交，对于大数据不行，因为地址栏存储体积有限。
	//post提交，提交的信息不显示地址栏中，显示在消息体中。post提交，可以提交大体积数据。 
	
    if (strcasecmp(method, "POST") == 0)
        cgi = 1;

    i = 0;
    while (ISspace(buf[j]) && (j < numchars))
        j++;
    while (!ISspace(buf[j]) && (i < sizeof(url) - 1) && (j < numchars))
    {
        url[i] = buf[j];
        i++; j++;
    }
    url[i] = '\0';
	//strcasecmp忽略大小写比较字符串
    if (strcasecmp(method, "GET") == 0)
    {
        query_string = url;
        while ((*query_string != '?') && (*query_string != '\0'))
            query_string++;
        if (*query_string == '?')
        {
            cgi = 1;
            *query_string = '\0';
            query_string++;
        }
    }

    sprintf(path, "htdocs%s", url);
    if (path[strlen(path) - 1] == '/')
		//extern char *strcat(char *dest, const char *src);
		//把src所指向的字符串（包括“\0”）复制到dest所指向的字符串后面（删除*dest原来末尾的“\0”）。
        strcat(path, "index.html");
	//stat返回值: 成功返回0，返回-1表示失败
    if (stat(path, &st) == -1) {
		//strcmp不忽略大小写比较字符串
		//一直用get_line读取文件，读到http头结束
        while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
            numchars = get_line(client, buf, sizeof(buf));
        not_found(client);
    }
	//执行这一步代表读取到了这个文件
    else
    {
		/*
		S_IFMT   0170000    文件类型的位遮罩
    	S_IFSOCK 0140000    套接字
    	S_IFLNK 0120000     符号连接
    	S_IFREG 0100000     一般文件
    	S_IFBLK 0060000     区块装置
    	S_IFDIR 0040000     目录
    	S_IFCHR 0020000     字符装置
    	S_IFIFO 0010000     先进先出
​
    	S_ISUID 04000     文件的(set user-id on execution)位
    	S_ISGID 02000     文件的(set group-id on execution)位
    	S_ISVTX 01000     文件的sticky位
​
    	S_IRUSR(S_IREAD) 00400     文件所有者具可读取权限
    	S_IWUSR(S_IWRITE)00200     文件所有者具可写入权限
    	S_IXUSR(S_IEXEC) 00100     文件所有者具可执行权限
​
    	S_IRGRP 00040             用户组具可读取权限
    	S_IWGRP 00020             用户组具可写入权限
    	S_IXGRP 00010             用户组具可执行权限
​
    	S_IROTH 00004             其他用户具可读取权限
    	S_IWOTH 00002             其他用户具可写入权限
    	S_IXOTH 00001             其他用户具可执行权限
		*/
		//是否是文件夹
        if ((st.st_mode & S_IFMT) == S_IFDIR)
            strcat(path, "/index.html");
		//文件所有者或文件所属组或其他人 具有可执行权限
        if ((st.st_mode & S_IXUSR) ||
                (st.st_mode & S_IXGRP) ||
                (st.st_mode & S_IXOTH)    )
            cgi = 1;
        if (!cgi)
			//执行这一步代表这个文件存在，但是不能执行
			//于是就换成读取文件内容再发送
            serve_file(client, path);
        else
            execute_cgi(client, path, method, query_string);
    }

    close(client);
}

/**********************************************************************/
/* Inform the client that a request it has made has a problem.
 * Parameters: client socket */
/**********************************************************************/
void bad_request(int client)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.0 400 BAD REQUEST\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "Content-type: text/html\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "<P>Your browser sent a bad request, ");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "such as a POST without a Content-Length.\r\n");
    send(client, buf, sizeof(buf), 0);
}

/**********************************************************************/
/* Put the entire contents of a file out on a socket.  This function
 * is named after the UNIX "cat" command, because it might have been
 * easier just to do something like pipe, fork, and exec("cat").
 * Parameters: the client socket descriptor
 *             FILE pointer for the file to cat */
/**********************************************************************/
void cat(int client, FILE *resource)
{
    char buf[1024];
	/*fgets函数功能为从指定的流中读取数据，每次读取一行。
	*其原型为：char *fgets(char *str, int n, FILE *stream);
	*从指定的流 stream 读取一行，并把它存储在 str 所指向的字符串内。
	*当读取 (n-1) 个字符时，或者读取到换行符时，或者到达文件末尾时，
	*它会停止，具体视情况而定。*/
    fgets(buf, sizeof(buf), resource);
	//feof是C语言标准库函数，其原型在stdio.h中，其功能是检测流上的文件结束符，如果文件结束，则返回非0值，否则返回0（即，文件结束：返回非0值，文件未结束，返回0值）
    while (!feof(resource))
    {
        send(client, buf, strlen(buf), 0);
        fgets(buf, sizeof(buf), resource);
    }
}

/**********************************************************************/
/* Inform the client that a CGI script could not be executed.
 * Parameter: the client socket descriptor. */
/**********************************************************************/
void cannot_execute(int client)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.0 500 Internal Server Error\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<P>Error prohibited CGI execution.\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* Print out an error message with perror() (for system errors; based
 * on value of errno, which indicates system call errors) and exit the
 * program indicating an error. */
/**********************************************************************/
void error_die(const char *sc)
{
    perror(sc);
    exit(1);
}

/**********************************************************************/
/* Execute a CGI script.  Will need to set environment variables as
 * appropriate.
 * Parameters: client socket descriptor
 *             path to the CGI script */
/**********************************************************************/
void execute_cgi(int client, const char *path,
        const char *method, const char *query_string)
{
    char buf[1024];
    int cgi_output[2];
    int cgi_input[2];
	//在头文件#include <bits/types.h>
	//pid_t等同于int
    pid_t pid;
    int status;
    int i;
    char c;
    int numchars = 1;
    int content_length = -1;

    buf[0] = 'A'; buf[1] = '\0';
    if (strcasecmp(method, "GET") == 0)
        while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
            numchars = get_line(client, buf, sizeof(buf));
    else if (strcasecmp(method, "POST") == 0) /*POST*/
    {
        numchars = get_line(client, buf, sizeof(buf));
        while ((numchars > 0) && strcmp("\n", buf))
        {
            buf[15] = '\0';
            if (strcasecmp(buf, "Content-Length:") == 0)
				/*atoi (表示 ascii to integer)是把字符串转换成整型数的一个函数，
				应用在计算机程序和办公软件中。int atoi(const char *nptr) 
				函数会扫描参数 nptr字符串，会跳过前面的空白字符
				（例如空格，tab缩进）等。
				如果 nptr不能转换成 int 或者 nptr为空字符串，那么将返回 0 */
                content_length = atoi(&(buf[16]));
            numchars = get_line(client, buf, sizeof(buf));
        }
        if (content_length == -1) {
            bad_request(client);
            return;
        }
    }
    else/*HEAD or other*/
    {
    }

	//pipe所需头文件 #include<unistd.h>
	//pipe函数定义中的fd参数是一个大小为2的一个数组类型的指针。
	//该函数成功时返回0，并将一对打开的文件描述符值填入fd参数指向的数组。
	//失败时返回 -1并设置errno。
    if (pipe(cgi_output) < 0) {
        cannot_execute(client);
        return;
    }
    if (pipe(cgi_input) < 0) {
        cannot_execute(client);
        return;
    }

    if ( (pid = fork()) < 0 ) {
        cannot_execute(client);
        return;
    }
    sprintf(buf, "HTTP/1.0 200 OK\r\n");
    send(client, buf, strlen(buf), 0);
    if (pid == 0)  /* child: CGI script */
    {
        char meth_env[255];
        char query_env[255];
        char length_env[255];
		/*#include <unistd.h>
		int dup(int oldfd);
		dup用来复制参数oldfd所指的文件描述符。
		当复制成功是，返回最小的尚未被使用过的文件描述符，
		若有错误则返回-1.错误代码存入errno中返回的新文件描述符和参数oldfd指向同一个文件，
		这两个描述符共享同一个数据结构，
		共享所有的锁定，读写指针和各项全现或标志位。
		假如oldfd的值为1，当前文件描述符的最小值为3，那么新描述符3指向描述符１所拥有的文件表项。*/
		//从shell中运行一个进程，默认会有3个文件描述符存在(0、１、2), 0与进程的标准输入相关联，１与进程的标准输出相关联，2与进程的标准错误输出相关联，
		/*dup2定义是int dup2( int filedes, int filedes2 ) 
		也是返回一个文件描述符，但是呢这个文件描述符你可以指定，
		也就是它的第二个参数filedes2，
		如果fiedes2文件描述符指定的文件已经被打开，
		那么就先把filedes2指定的文件关闭，
		同样还是返回文件描述符这个文件描述符可以用来打开filedes1指定的文件*/
        dup2(cgi_output[1], STDOUT);
        dup2(cgi_input[0], STDIN);
		//#include <unistd.h>  int close(int fd); 返回值：成功返回0，出错返回-1并设置errno
		//参数fd是要关闭的文件描述符。
        close(cgi_output[0]);
        close(cgi_input[1]);
        sprintf(meth_env, "REQUEST_METHOD=%s", method);
		//putenv  就是把meth_env添加到环境变量里，且这个环境变量只在这个子进程里有用
        putenv(meth_env);
        if (strcasecmp(method, "GET") == 0) {
            sprintf(query_env, "QUERY_STRING=%s", query_string);
            putenv(query_env);
        }
        else {   /* POST */
            sprintf(length_env, "CONTENT_LENGTH=%d", content_length);
            putenv(length_env);
        }
		//Linux下头文件 #include <unistd.h> 函数定义 int execl(const char *path, const char *arg, ...);
        /*第一参数path字符指针所指向要执行的文件路径， 
		接下来的参数代表执行该文件时传递的参数列表：argv[0],argv[1]... 
		最后一个参数须用空指针NULL作结束。*/
		// 例如执行/bin目录下的ls, 第一参数为程序名ls, 第二个参数为"-al", 第三个参数为"/etc/"
		//execl("/bin/ls","ls","-al","/etc/",NULL)；
		// 执行：  ./execl   结果：-rw-r--r-- 1 root root 2218 Jan 13 11:36 /etc/passwd
		execl(path, NULL);
        exit(0);
    } else {    /* parent */
        close(cgi_output[1]);
        close(cgi_input[0]);
        if (strcasecmp(method, "POST") == 0)
            for (i = 0; i < content_length; i++) {
                recv(client, &c, 1, 0);
                write(cgi_input[1], &c, 1);
            }
        while (read(cgi_output[0], &c, 1) > 0)
            send(client, &c, 1, 0);

        close(cgi_output[0]);
        close(cgi_input[1]);
        waitpid(pid, &status, 0);
    }
}

/**********************************************************************/
/* Get a line from a socket, whether the line ends in a newline,
 * carriage return, or a CRLF combination.  Terminates the string read
 * with a null character.  If no newline indicator is found before the
 * end of the buffer, the string is terminated with a null.  If any of
 * the above three line terminators is read, the last character of the
 * string will be a linefeed and the string will be terminated with a
 * null character.
 * Parameters: the socket descriptor
 *             the buffer to save the data in
 *             the size of the buffer
 * Returns: the number of bytes stored (excluding null) */
/**********************************************************************/
int get_line(int sock, char *buf, int size)
{
    int i = 0;
    char c = '\0';
    int n;

    while ((i < size - 1) && (c != '\n'))
    {
		//recv函数仅仅是copy数据，真正的接收数据是协议来完成的
		//int recv( _In_ SOCKET s, _Out_ char *buf, _In_ int len, _In_ int flags);
        //len  缓冲区长度。  flags 指定调用方式。
		//recv函数返回其实际copy的字节数。如果recv在copy时出错，那么它返回SOCKET_ERROR；如果recv函数在等待协议接收数据时网络中断了，那么它返回0。
		n = recv(sock, &c, 1, 0);
        /* DEBUG printf("%02X\n", c); */
        if (n > 0)
        {
            if (c == '\r')
            {
				//把flags设置为MSG_PEEK，仅把tcp buffer中的数据读取到
				//buf中，并不把已读取的数据从tcp buffer中移除，
				//再次调用recv仍然可以读到刚才读到的数据。
                n = recv(sock, &c, 1, MSG_PEEK);
                /* DEBUG printf("%02X\n", c); */
                if ((n > 0) && (c == '\n'))
                    recv(sock, &c, 1, 0);
                else
                    c = '\n';
            }
			//buf中没有\r只会在结尾保存\n
            buf[i] = c;
            i++;
        }
        else
            c = '\n';
    }
    buf[i] = '\0';

    return(i);
}

/**********************************************************************/
/* Return the informational HTTP headers about a file. */
/* Parameters: the socket to print the headers on
 *             the name of the file */
/**********************************************************************/
void headers(int client, const char *filename)
{
	//这个filename是一个文件路径
    char buf[1024];
    (void)filename;  /* could use filename to determine file type */

    strcpy(buf, "HTTP/1.0 200 OK\r\n");
    send(client, buf, strlen(buf), 0);
    strcpy(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    strcpy(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* Give a client a 404 not found status message. */
/**********************************************************************/
void not_found(int client)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.0 404 NOT FOUND\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<HTML><TITLE>Not Found</TITLE>\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<BODY><P>The server could not fulfill\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "your request because the resource specified\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "is unavailable or nonexistent.\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</BODY></HTML>\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* Send a regular file to the client.  Use headers, and report
 * errors to client if they occur.
 * Parameters: a pointer to a file structure produced from the socket
 *              file descriptor
 *             the name of the file to serve */
/**********************************************************************/
void serve_file(int client, const char *filename)
{
	//filename保存的是文件路径
    FILE *resource = NULL;
    int numchars = 1;
    char buf[1024];

    buf[0] = 'A'; buf[1] = '\0';
	//和前边一样读取整个http头文件并不做任何操作
    while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
        numchars = get_line(client, buf, sizeof(buf));
	//进入这一步就是因为没有执行权限，就采用读取文件的方式
    resource = fopen(filename, "r");
    if (resource == NULL)
        not_found(client);
    else
    {
		//先返回一个文件存在的http响应 200 0k
        headers(client, filename);
        cat(client, resource);
    }
    fclose(resource);
}

/**********************************************************************/
/* This function starts the process of listening for web connections
 * on a specified port.  If the port is 0, then dynamically allocate a
 * port and modify the original port variable to reflect the actual
 * port.
 * Parameters: pointer to variable containing the port to connect on
 * Returns: the socket */
/**********************************************************************/
int startup(u_short *port)
{
    int httpd = 0;
    int on = 1;
    struct sockaddr_in name;

    httpd = socket(PF_INET, SOCK_STREAM, 0);
    if (httpd == -1)
        error_die("socket");
    memset(&name, 0, sizeof(name));
    name.sin_family = AF_INET;
    name.sin_port = htons(*port);
	//INADDR_ANY（地址通配符）表示这个服务器上任意一个IP地址都可以
    name.sin_addr.s_addr = htonl(INADDR_ANY);
	/*int getsockopt(int sock, int level, int optname, 
		void *optval, socklen_t *optlen);
	int setsockopt(int sock, int level, int optname, const 
		void *optval, socklen_t optlen);
	sock：将要被设置或者获取选项的套接字。
	level：选项所在的协议层。
		1)SOL_SOCKET:通用套接字选项.
		2)IPPROTO_IP:IP选项.
		3)IPPROTO_TCP:TCP选项.
	optname：需要访问的选项名。
	optval：对于getsockopt()，指向返回选项值的缓冲。
			对于setsockopt()，指向包含新选项值的缓冲。
	optlen：对于getsockopt()，作为入口参数时，选项值的最大长度。
			作为出口参数时，选项值的实际长度。对于setsockopt()，
			现选项的长度。
	成功执行时，返回0。失败返回-1*/
    if ((setsockopt(httpd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0)  
    //setsockopt获取或者设置与某个套接字关联的选项。
	{  
        error_die("setsockopt failed");
    }
	/*struct sockaddr {
　　unsigned short sa_family; // address family, AF_xxx 
　　char sa_data[14]; // 14 bytes of protocol address 
　　};*/
    if (bind(httpd, (struct sockaddr *)&name, sizeof(name)) < 0)
        error_die("bind");
	//如果不指定端口就动态分配一个
    if (*port == 0)  /* if dynamically allocating a port */
    {
        socklen_t namelen = sizeof(name);
		/*getsockname()函数用于获取一个套接字的名字。
		*它用于一个已捆绑或已连接套接字s，本地地址将被返回。
		*本调用特别适用于如下情况：未调用bind()就调用了connect()，
		*这时唯有getsockname()调用可以获知系统内定的本地地址。
		*在返回时，namelen参数包含了名字的实际字节数。
		*若无错误发生，getsockname()返回0。
		int PASCAL FAR getsockname( SOCKET s, 
			struct sockaddr FAR* name,int FAR* namelen);
		s：标识一个已捆绑套接口的描述字。
		name：接收套接口的地址（名字）。
		namelen：名字缓冲区长度。*/
        if (getsockname(httpd, (struct sockaddr *)&name, &namelen) == -1)
            error_die("getsockname");
        *port = ntohs(name.sin_port);
    }
	
	/*int listen( int sockfd, int backlog);
	*sockfd：用于标识一个已捆绑未连接套接口的描述字。
	*backlog：等待连接队列的最大长度。
	*置服务器的流套接字处于监听状态
	仅面向连接的流套接字
	成功返回零 失败socket_error*/
	
    if (listen(httpd, 5) < 0)
        error_die("listen");
    return(httpd);
}

/**********************************************************************/
/* Inform the client that the requested web method has not been
 * implemented.
 * Parameter: the client socket */
/**********************************************************************/
void unimplemented(int client)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.0 501 Method Not Implemented\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<HTML><HEAD><TITLE>Method Not Implemented\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</TITLE></HEAD>\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<BODY><P>HTTP request method not supported.\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</BODY></HTML>\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/

int main(void)
{
    int server_sock = -1;
    u_short port = 4000;
    int client_sock = -1;
	//struct sockaddr_in
 	//{
	//short sin_family;/*Address family一般来说AF_INET（地址族）PF_INET（协议族）*/
	//unsigned short sin_port;/*Port number(必须要采用网络数据格式,普通数字可以用htons()函数转换成网络数据格式的数字)*/
	//struct in_addr sin_addr;/*IP address in network byte order（Internet address）*/
	//unsigned char sin_zero[8];/*Same size as struct sockaddr没有实际意义,只是为了　跟SOCKADDR结构在内存中对齐*/
	//};
    struct sockaddr_in client_name;
	//为了方便平台移植而定义的内存类型，大小在所有平台上都是四个字节
    socklen_t  client_name_len = sizeof(client_name);
	//Linux下没有真正意义上的线程，他的实现是由进程来模拟，所以属于用户级线程位于libpthread共享库（所以线程的ID只在库中有效）
	//Linux 实现进程的主要目的是资源独占，Linux实现线程的主要目的是资源共享，线程所有资源由进程提供
	//同一个进程的多个线程共享同一地址空间
    pthread_t newthread;

    server_sock = startup(&port);
    printf("httpd running on port %d\n", port);

    while (1)
    {
		/*SOCKET accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
		*服务器调用accept函数从处于监听状态的流套接字sd的客户连接队列中
		*取出排在最前面的的一个客户连接请求，
		*并创建一个与sd同类的新套接字描述符与客户端套接字创建连接通道。*/
        client_sock = accept(server_sock,
                (struct sockaddr *)&client_name,
                &client_name_len);
        if (client_sock == -1)
            error_die("accept");
        /* accept_request(&client_sock);
		int pthread_create(pthread_t * thread, const pthread_arrt_t* attr
			,void*(*start_routine)(void *), void* arg);
		（1）thread参数是新线程的标识符,为一个整型。

		（2）attr参数用于设置新线程的属性。
			给传递NULL表示设置为默认线程属性。

		（3）start_routine和arg参数分别指定新线程将运行的函数和参数。
			start_routine返回时,这个线程就退出了

		（4）返回值:成功返回0,失败返回错误号。*/
		//intptr_t是为了保存指针变量的，由于不同位数的机器指针变量所占字节数不同。为了保证平台的通用性
        if (pthread_create(&newthread , NULL, (void *)accept_request, (void *)(intptr_t)client_sock) != 0)
            perror("pthread_create");
    }

    close(server_sock);

    return(0);
}
