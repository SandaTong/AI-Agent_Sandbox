// -----------------------------------------------------------------------------
// minifilter/sandbox_minifilter.c
// -----------------------------------------------------------------------------
// 【M9】文件系统 Minifilter 驱动（形态 A+B：审计 + 拦截 + 用户态下发策略）。
//
// 挂在 FltMgr（fltmgr.sys）下，在 IRP_MJ_CREATE 的 Pre 回调里：
//   1) 拿发起进程 PID + 目标文件规范化路径
//   2) 查用户态下发的敏感路径黑名单
//      - 命中  -> 设 STATUS_ACCESS_DENIED + FLT_PREOP_COMPLETE（内核拦截，形态 B）
//      - 未命中-> 放行（FLT_PREOP_SUCCESS_NO_CALLBACK）
//   3) 无论放行/拦截，都通过 FltMgr 通信端口把一条审计记录上报用户态（形态 A）
//
// 用户态通过通信端口下发 MfPolicyUpdate 覆盖黑名单（形态 B 的策略来源）。
//
// ⚠️ 内核代码铁律：
//   - 不可信输入（用户态下发的策略）全部边界校验后才用
//   - 字符串操作用带长度上限的安全版本，杜绝溢出（内核溢出 = 蓝屏/提权漏洞）
//   - 分页/非分页内存与 IRQL 要匹配（PreCreate 在 PASSIVE_LEVEL，可安全取文件名）
// -----------------------------------------------------------------------------
#include <fltKernel.h>
#include <ntddk.h>

#include "mf_protocol.h"

// -----------------------------------------------------------------------------
// 全局状态
// -----------------------------------------------------------------------------
static PFLT_FILTER    g_filter = NULL;          // FltRegisterFilter 返回的过滤器句柄
static PFLT_PORT      g_server_port = NULL;      // 通信端口服务端（内核建）
static PFLT_PORT      g_client_port = NULL;      // 已连接的用户态客户端（仅允许一个）

// 敏感路径黑名单（用户态下发，整表覆盖）。用自旋锁保护并发读写。
static struct MfPolicyUpdate g_policy;           // 当前策略（rule_count 条）
static KSPIN_LOCK            g_policy_lock;

// -----------------------------------------------------------------------------
// 前置声明
// -----------------------------------------------------------------------------
DRIVER_INITIALIZE DriverEntry;
NTSTATUS MiniUnload(FLT_FILTER_UNLOAD_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS PreCreate(PFLT_CALLBACK_DATA Data,
                                    PCFLT_RELATED_OBJECTS FltObjects,
                                    PVOID *CompletionContext);
NTSTATUS MiniInstanceSetup(PCFLT_RELATED_OBJECTS FltObjects,
                           FLT_INSTANCE_SETUP_FLAGS Flags,
                           DEVICE_TYPE VolumeDeviceType,
                           FLT_FILESYSTEM_TYPE VolumeFilesystemType);
NTSTATUS MiniQueryTeardown(PCFLT_RELATED_OBJECTS FltObjects,
                           FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);
NTSTATUS PortConnect(PFLT_PORT ClientPort, PVOID ServerPortCookie,
                     PVOID ConnectionContext, ULONG SizeOfContext,
                     PVOID *ConnectionPortCookie);
VOID PortDisconnect(PVOID ConnectionCookie);
NTSTATUS PortMessage(PVOID PortCookie, PVOID InputBuffer, ULONG InputBufferLength,
                     PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnOutputBufferLength);

// -----------------------------------------------------------------------------
// 回调注册表
// -----------------------------------------------------------------------------
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, PreCreate, NULL },   // 只做 Pre-Create，不需要 Post
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                       // Flags
    NULL,                    // ContextRegistration
    Callbacks,
    MiniUnload,
    MiniInstanceSetup,
    MiniQueryTeardown,
    NULL,                    // InstanceTeardownStart
    NULL,                    // InstanceTeardownComplete
    NULL, NULL, NULL, NULL   // 其它可选回调
};

// -----------------------------------------------------------------------------
// 大写化（内核态，供大小写不敏感包含匹配）。就地改写 buf 前 n 个字符。
// -----------------------------------------------------------------------------
static VOID ToUpperInplace(PWCHAR buf, ULONG n) {
    for (ULONG i = 0; i < n; ++i)
        buf[i] = RtlUpcaseUnicodeChar(buf[i]);
}

// 大小写不敏感的"子串包含"：haystack 是否包含 needle。二者均已大写。
static BOOLEAN ContainsW(const WCHAR *haystack, ULONG hlen, const WCHAR *needle, ULONG nlen) {
    if (nlen == 0 || nlen > hlen)
        return FALSE;
    for (ULONG i = 0; i + nlen <= hlen; ++i) {
        ULONG j = 0;
        for (; j < nlen; ++j) {
            if (haystack[i + j] != needle[j])
                break;
        }
        if (j == nlen)
            return TRUE;
    }
    return FALSE;
}

// -----------------------------------------------------------------------------
// 上报一条审计记录到用户态（若已连接客户端）。
// FltSendMessage 在 PASSIVE_LEVEL 调用；用一个短超时避免用户态没收时卡住内核。
// -----------------------------------------------------------------------------
static VOID SendAudit(ULONG pid, ULONG verdict, const WCHAR *path, ULONG path_chars) {
    if (g_client_port == NULL)
        return;

    struct MfAuditRecord rec;
    RtlZeroMemory(&rec, sizeof(rec));
    rec.msg_type = kMfAudit;
    rec.verdict = verdict;
    rec.process_id = pid;

    if (path_chars > MF_MAX_PATH_CHARS - 1)
        path_chars = MF_MAX_PATH_CHARS - 1;
    rec.path_chars = path_chars;
    if (path_chars > 0)
        RtlCopyMemory(rec.path, path, path_chars * sizeof(WCHAR));

    LARGE_INTEGER timeout;
    timeout.QuadPart = -10 * 1000 * 500;  // 50ms（相对时间，100ns 单位，负值）
    FltSendMessage(g_filter, &g_client_port, &rec, sizeof(rec), NULL, NULL, &timeout);
}

// -----------------------------------------------------------------------------
// 判定：path（大写）是否命中当前黑名单任一关键词。
// -----------------------------------------------------------------------------
static BOOLEAN IsBlocked(const WCHAR *upath, ULONG upath_chars) {
    BOOLEAN blocked = FALSE;
    KIRQL old;
    KeAcquireSpinLock(&g_policy_lock, &old);
    ULONG cnt = g_policy.rule_count;
    if (cnt > MF_MAX_RULES)
        cnt = MF_MAX_RULES;
    for (ULONG i = 0; i < cnt; ++i) {
        ULONG rlen = g_policy.rules[i].len_chars;
        if (rlen == 0 || rlen > MF_MAX_PATH_CHARS)
            continue;
        if (ContainsW(upath, upath_chars, g_policy.rules[i].text, rlen)) {
            blocked = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_policy_lock, old);
    return blocked;
}

// -----------------------------------------------------------------------------
// Pre-Create：审计 + 拦截核心
// -----------------------------------------------------------------------------
FLT_PREOP_CALLBACK_STATUS PreCreate(PFLT_CALLBACK_DATA Data,
                                    PCFLT_RELATED_OBJECTS FltObjects,
                                    PVOID *CompletionContext) {
    UNREFERENCED_PARAMETER(CompletionContext);

    // 跳过内核自身发起的 I/O（Data->RequestorMode == KernelMode），只看用户态请求。
    if (Data->RequestorMode == KernelMode)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PFLT_FILE_NAME_INFORMATION name_info = NULL;
    NTSTATUS st = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name_info);
    if (!NT_SUCCESS(st) || name_info == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;  // 拿不到名字就放行（不因过滤器故障挡业务）

    FltParseFileNameInformation(name_info);

    // name_info->Name 是完整规范化路径（如 \Device\HarddiskVolume3\secret\a.txt）。
    // 拷到本地缓冲并大写，做包含匹配。
    ULONG chars = name_info->Name.Length / sizeof(WCHAR);
    if (chars > MF_MAX_PATH_CHARS - 1)
        chars = MF_MAX_PATH_CHARS - 1;

    WCHAR upath[MF_MAX_PATH_CHARS];
    RtlZeroMemory(upath, sizeof(upath));
    RtlCopyMemory(upath, name_info->Name.Buffer, chars * sizeof(WCHAR));
    ToUpperInplace(upath, chars);

    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    BOOLEAN blocked = IsBlocked(upath, chars);

    // 审计上报（形态 A）：放行/拦截都报，用原始路径（未大写更可读，这里用大写版即可）。
    SendAudit(pid, blocked ? kMfBlocked : kMfAllowed, upath, chars);

    FltReleaseFileNameInformation(name_info);

    if (blocked) {
        // 形态 B：从内核挡住这次打开，请求不再下发给 ntfs.sys。
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// -----------------------------------------------------------------------------
// 实例 setup / teardown：挂载到每个卷时被调。demo 全部接受。
// -----------------------------------------------------------------------------
NTSTATUS MiniInstanceSetup(PCFLT_RELATED_OBJECTS FltObjects,
                           FLT_INSTANCE_SETUP_FLAGS Flags,
                           DEVICE_TYPE VolumeDeviceType,
                           FLT_FILESYSTEM_TYPE VolumeFilesystemType) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    return STATUS_SUCCESS;  // accept mount on this volume
}

NTSTATUS MiniQueryTeardown(PCFLT_RELATED_OBJECTS FltObjects,
                           FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;  // 允许卸载
}

// -----------------------------------------------------------------------------
// 通信端口：连接 / 断开 / 收消息（策略下发）
// -----------------------------------------------------------------------------
NTSTATUS PortConnect(PFLT_PORT ClientPort, PVOID ServerPortCookie,
                     PVOID ConnectionContext, ULONG SizeOfContext,
                     PVOID *ConnectionPortCookie) {
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionPortCookie);
    g_client_port = ClientPort;  // demo 只允许一个客户端
    return STATUS_SUCCESS;
}

VOID PortDisconnect(PVOID ConnectionCookie) {
    UNREFERENCED_PARAMETER(ConnectionCookie);
    FltCloseClientPort(g_filter, &g_client_port);
    g_client_port = NULL;
}

// 用户态 -> 内核：策略下发。严格校验后整表覆盖 g_policy。
NTSTATUS PortMessage(PVOID PortCookie, PVOID InputBuffer, ULONG InputBufferLength,
                     PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnOutputBufferLength) {
    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (ReturnOutputBufferLength)
        *ReturnOutputBufferLength = 0;

    // 不信任对端：长度必须正好是一个 MfPolicyUpdate。
    if (InputBuffer == NULL || InputBufferLength < sizeof(struct MfPolicyUpdate))
        return STATUS_INVALID_PARAMETER;

    // InputBuffer 是用户态内存，FltMgr 已在当前进程上下文映射，可直接读；
    // 但仍要用 try/except 防御非法指针（这里用结构化异常）。
    struct MfPolicyUpdate incoming;
    __try {
        RtlCopyMemory(&incoming, InputBuffer, sizeof(incoming));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_INVALID_USER_BUFFER;
    }

    if (incoming.msg_type != kMfPolicySet)
        return STATUS_INVALID_PARAMETER;
    if (incoming.rule_count > MF_MAX_RULES)
        return STATUS_INVALID_PARAMETER;

    // 逐条大写 + 夹紧长度，然后整表覆盖（自旋锁保护）。
    for (ULONG i = 0; i < incoming.rule_count; ++i) {
        if (incoming.rules[i].len_chars > MF_MAX_PATH_CHARS - 1)
            incoming.rules[i].len_chars = MF_MAX_PATH_CHARS - 1;
        ToUpperInplace(incoming.rules[i].text, incoming.rules[i].len_chars);
    }

    KIRQL old;
    KeAcquireSpinLock(&g_policy_lock, &old);
    RtlCopyMemory(&g_policy, &incoming, sizeof(g_policy));
    KeReleaseSpinLock(&g_policy_lock, old);

    return STATUS_SUCCESS;
}

// -----------------------------------------------------------------------------
// 卸载
// -----------------------------------------------------------------------------
NTSTATUS MiniUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);
    if (g_server_port)
        FltCloseCommunicationPort(g_server_port);
    if (g_filter)
        FltUnregisterFilter(g_filter);
    g_server_port = NULL;
    g_filter = NULL;
    return STATUS_SUCCESS;
}

// -----------------------------------------------------------------------------
// DriverEntry：注册过滤器 + 建通信端口 + 开始过滤
// -----------------------------------------------------------------------------
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    KeInitializeSpinLock(&g_policy_lock);
    RtlZeroMemory(&g_policy, sizeof(g_policy));

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_filter);
    if (!NT_SUCCESS(status))
        return status;

    // ---- 建通信端口（用户态用 FilterConnectCommunicationPort 连 MF_PORT_NAME）----
    // 端口 SD：只允许 Administrator + SYSTEM 连（防低权限进程乱下发策略）。
    PSECURITY_DESCRIPTOR sd = NULL;
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (NT_SUCCESS(status)) {
        UNICODE_STRING port_name;
        RtlInitUnicodeString(&port_name, MF_PORT_NAME);

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &port_name,
                                   OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);

        status = FltCreateCommunicationPort(g_filter, &g_server_port, &oa, NULL,
                                            PortConnect, PortDisconnect, PortMessage,
                                            1 /*maxConnections*/);
        FltFreeSecurityDescriptor(sd);
    }
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_filter);
        g_filter = NULL;
        return status;
    }

    status = FltStartFiltering(g_filter);
    if (!NT_SUCCESS(status)) {
        FltCloseCommunicationPort(g_server_port);
        FltUnregisterFilter(g_filter);
        g_server_port = NULL;
        g_filter = NULL;
        return status;
    }

    return STATUS_SUCCESS;
}
