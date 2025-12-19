#ifndef FRAME_ANALYZER_H
#define FRAME_ANALYZER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// 分析器句柄
typedef void* frame_analyzer_handle_t;

// 创建分析器实例
frame_analyzer_handle_t frame_analyzer_create(void);

// 销毁分析器实例
void frame_analyzer_destroy(frame_analyzer_handle_t handle);

// 附加应用进程（PID）
int frame_analyzer_attach_app(frame_analyzer_handle_t handle, int pid);

// 分离应用进程（PID）
int frame_analyzer_detach_app(frame_analyzer_handle_t handle, int pid);

// 分离所有应用进程
void frame_analyzer_detach_all(frame_analyzer_handle_t handle);

// 阻塞接收帧时间（timeout_ms=0表示无限阻塞）
// 成功返回0，超时返回-1，错误返回负数
int frame_analyzer_recv(
    frame_analyzer_handle_t handle,
    int* pid,
    uint64_t* frametime_ns,
    int timeout_ms
);

// 非阻塞接收帧时间
// 成功返回0，无数据返回1，错误返回负数
int frame_analyzer_try_recv(
    frame_analyzer_handle_t handle,
    int* pid,
    uint64_t* frametime_ns
);

// 检查是否监控指定PID（1=是，0=否，负数=错误）
int frame_analyzer_is_monitoring(frame_analyzer_handle_t handle, int pid);

// 获取最后错误信息（返回C字符串，需自行释放）
const char* frame_analyzer_get_last_error(frame_analyzer_handle_t handle);

// 获取版本号（返回C字符串）
const char* frame_analyzer_get_version(void);

#ifdef __cplusplus
}
#endif

#endif // FRAME_ANALYZER_H
