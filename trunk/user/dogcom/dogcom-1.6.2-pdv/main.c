#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "configparse.h"
#include "auth.h"

#ifdef linux
#include <limits.h>
#include "daemon.h"
#include "eapol.h"
#include "libs/common.h"
#endif

#define VERSION "1.6.2"

void print_help(int exval);
int try_smart_eaplogin(void);

static const char default_bind_ip[20] = "0.0.0.0";

int main(int argc, char *argv[]) {
    if (argc == 1) {
        print_help(1);
    }

    char *file_path;

    while (1) {
        static const struct option long_options[] = {
            { "mode", required_argument, 0, 'm' },
            { "conf", required_argument, 0, 'c' },
            { "bindip", required_argument, 0, 'b' },
            { "log", required_argument, 0, 'l' },
#ifdef linux
            { "daemon", no_argument, 0, 'd' },
            { "802.1x", no_argument, 0, 'x' },
#endif
            { "eternal", no_argument, 0, 'e' },
            { "verbose", no_argument, 0, 'v' },
            { "help", no_argument, 0, 'h' },
            { 0, 0, 0, 0 }
        };

        int c;
        int option_index = 0;
#ifdef linux
        c = getopt_long(argc, argv, "m:c:b:l:dxevh", long_options, &option_index);
#else
        c = getopt_long(argc, argv, "m:c:b:l:evh", long_options, &option_index);
#endif

        if (c == -1) {
            break;
        }
        switch (c) {
            case 'm':
                if (strcmp(optarg, "dhcp") == 0) {
                    strcpy(mode, optarg);
                } else if (strcmp(optarg, "pppoe") == 0) {
                    strcpy(mode, optarg);
                } else {
                    printf("未知模式\n");
                    exit(1);
                }
                break;
            case 'c':
#ifndef __APPLE__
                if (mode != NULL) {
#endif
#ifdef linux
                    char path_c[PATH_MAX];
                    realpath(optarg, path_c);
                    file_path = strdup(path_c);
#else
                    file_path = optarg;
#endif
#ifndef __APPLE__
                }
#endif
                break;
            case 'b':
                strcpy(bind_ip, optarg);
                break;
            case 'l':
#ifndef __APPLE__
                if (mode != NULL) {
#endif
#ifdef linux
                    char path_l[PATH_MAX];
                    realpath(optarg, path_l);
                    log_path = strdup(path_l);
#else
                    log_path = optarg;
#endif
                    logging_flag = 1;
#ifndef __APPLE__
                }
#endif
                break;
#ifdef linux
            case 'd':
                daemon_flag = 1;
                break;
            case 'x':
                eapol_flag = 1;
                break;
#endif
            case 'e':
                eternal_flag = 1;
                break;
            case 'v':
                verbose_flag = 1;
                break;
            case 'h':
                print_help(0);
                break;
            case '?':
                print_help(1);
                break;
            default:
                break;
        }
    }

#ifndef __APPLE__
    if (mode != NULL && file_path != NULL) {
#endif
#ifdef linux
        if (daemon_flag) {
            daemonise();
        }
#endif

#ifdef WIN32 // dirty fix with win32
        char tmp[10] = {0};
        strcpy(tmp, mode);
#endif
        if (!config_parse(file_path)) {
#ifdef WIN32 // dirty fix with win32
            strcpy(mode, tmp);
#endif

#ifdef linux
            if (eapol_flag) { // eable 802.1x authorization
                if (0 != try_smart_eaplogin()) {
                    printf("Can't finish 802.1x authorization!\n");
                    return 1;
                }
            }
#endif
            if (strlen(bind_ip) == 0) {
                memcpy(bind_ip, default_bind_ip, sizeof(default_bind_ip));
            }
            dogcom(5);
        } else {
            return 1;
        }
#ifndef __APPLE__
    } else {
        printf("Need more options!\n\n");
        return 1;
    }
#endif
    return 0;
}

void print_help(int exval) {
    printf(
        "       __                               \n"
        "  ____/ /___  ____ __________  ____ ___ \n"
        " / __  / __ \\/ __ `/ ___/ __ \\/ __ `__ \\ \n"
        "/ /_/ / /_/ / /_/ / /__/ /_/ / / / / / /\n"
        "\\__,_/\\____/\\__, /\\___/\\____/_/ /_/ /_/ \n"
        "           /____/ zh-Hans                      \n"
    );
    printf("一个基于原版汉化的dogcom 版本： %s\n",VERSION);
    printf("默认配置文件基于武汉工程科技学院\n");
    printf("功能与原版一致，如需查看原版log请打开log记录\n");

    printf("\nDrcom-generic的C语言版本.\n");

    printf("使用方法:\n");
    printf("\tdogcom -m <dhcp/pppoe> -c <FILEPATH> [options <argument>]...\n\n");

    printf("参数:\n");
    printf("\t--mode <dhcp/pppoe>, -m <dhcp/pppoe>  认证方式 \n");
    printf("\t--conf <配置文件路径>, -c <配置文件路径>\n");      
    printf("\t                                      认证配置文件路径\n");
    printf("\t--bindip <IPADDR>, -b <IPADDR>\n");    
    printf("\t                                      绑定ip默认0.0.0.0\n");
    printf("\t                                      此选项可以不用填\n");
    printf("\t--log <日志文件路径>, -l <日志文件路径> \n");  
    printf("\t                  	  	      日志文件输出路径\n");

#ifdef linux
    printf("\t--daemon, -d                          保持进程一直在后台\n");
    printf("\t--802.1x, -x                          打开802.1x认证\n");
#endif
    printf("\t--eternal, -e                         如果认证失败就重试\n");
    printf("\t--verbose, -v                         在控制台输出日志\n");
    printf("\t--help, -h                            显示帮助\n\n");
    exit(exval);
}

#ifdef linux
int try_smart_eaplogin(void)
{
#define IFS_MAX     (64)
    int ifcnt = IFS_MAX;
    iflist_t ifs[IFS_MAX];
    if (0 > getall_ifs(ifs, &ifcnt))
        return -1;

    for (int i = 0; i < ifcnt; ++i) {
        setifname(ifs[i].name);
        if (0 == eaplogin(drcom_config.username, drcom_config.password))
            return 0;
    }
    return -1;
}
#endif