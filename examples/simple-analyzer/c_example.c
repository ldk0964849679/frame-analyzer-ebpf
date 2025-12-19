#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include "../include/frame_analyzer.h"

volatile sig_atomic_t running = 1;

void sig_handler(int sig) {
    running = 0;
        printf("\nReceived signal %d, stopping...\n", sig);
        }

        int main(int argc, char* argv[]) {
            if (argc < 2) {
                    fprintf(stderr, "Usage: %s <pid1> [pid2 ...]\n", argv[0]);
                            return 1;
                                }

                                    // 注册信号处理
                                        signal(SIGINT, sig_handler);
                                            signal(SIGTERM, sig_handler);

                                                // 打印库信息
                                                    printf("Frame Analyzer C Example\n");
                                                        printf("Version: %s\n", frame_analyzer_get_version());

                                                            // 创建分析器
                                                                frame_analyzer_handle_t analyzer = frame_analyzer_create();
                                                                    if (!analyzer) {
                                                                            fprintf(stderr, "Create analyzer failed: %s\n", frame_analyzer_get_last_error(analyzer));
                                                                                    return 1;
                                                                                        }
                                                                                            printf("Analyzer created successfully\n");

                                                                                                // 附加所有指定PID
                                                                                                    for (int i = 1; i < argc; i++) {
                                                                                                            int pid = atoi(argv[i]);
                                                                                                                    int ret = frame_analyzer_attach_app(analyzer, pid);
                                                                                                                            if (ret == 0) {
                                                                                                                                        printf("Attached PID %d\n", pid);
                                                                                                                                                } else {
                                                                                                                                                            fprintf(stderr, "Attach PID %d failed (code %d): %s\n", 
                                                                                                                                                                                pid, ret, frame_analyzer_get_last_error(analyzer));
                                                                                                                                                                                        }
                                                                                                                                                                                            }

                                                                                                                                                                                                // 监控循环
                                                                                                                                                                                                    printf("\nMonitoring frame time... (Press Ctrl+C to stop)\n");
                                                                                                                                                                                                        uint64_t frame_cnt = 0;
                                                                                                                                                                                                            while (running) {
                                                                                                                                                                                                                    int pid;
                                                                                                                                                                                                                            uint64_t frametime_ns;
                                                                                                                                                                                                                                    int ret = frame_analyzer_recv(analyzer, &pid, &frametime_ns, 100);

                                                                                                                                                                                                                                            if (ret == 0) {
                                                                                                                                                                                                                                                        frame_cnt++;
                                                                                                                                                                                                                                                                    double frametime_ms = frametime_ns / 1000000.0;
                                                                                                                                                                                                                                                                                double fps = 1000000000.0 / frametime_ns;
                                                                                                                                                                                                                                                                                            printf("Frame #%llu: PID=%d, Time=%.2fms, FPS=%.2f\n",
                                                                                                                                                                                                                                                                                                               (unsigned long long)frame_cnt, pid, frametime_ms, fps);
                                                                                                                                                                                                                                                                                                                       } else if (ret == -1) {
                                                                                                                                                                                                                                                                                                                                   // 超时，继续循环
                                                                                                                                                                                                                                                                                                                                               continue;
                                                                                                                                                                                                                                                                                                                                                       } else {
                                                                                                                                                                                                                                                                                                                                                                   fprintf(stderr, "Recv failed (code %d): %s\n", ret, frame_analyzer_get_last_error(analyzer));
                                                                                                                                                                                                                                                                                                                                                                               break;
                                                                                                                                                                                                                                                                                                                                                                                       }
                                                                                                                                                                                                                                                                                                                                                                                           }

                                                                                                                                                                                                                                                                                                                                                                                               // 清理资源
                                                                                                                                                                                                                                                                                                                                                                                                   frame_analyzer_detach_all(analyzer);
                                                                                                                                                                                                                                                                                                                                                                                                       frame_analyzer_destroy(analyzer);

                                                                                                                                                                                                                                                                                                                                                                                                           printf("\nTotal frames received: %llu\n", (unsigned long long)frame_cnt);
                                                                                                                                                                                                                                                                                                                                                                                                               printf("Exit successfully\n");
                                                                                                                                                                                                                                                                                                                                                                                                                   return 0;
                                                                                                                                                                                                                                                                                                                                                                                                                   }