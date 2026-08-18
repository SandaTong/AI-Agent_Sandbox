// -----------------------------------------------------------------------------
// core/file_acl.h
// -----------------------------------------------------------------------------
// 【M8 形态 B】用 NTFS DACL 从"外部"摘掉 target 对某目录的写权限。
//
// 【和形态 A（IPC 文件 Broker）的关系——两条互补的路线】
//   形态 A：target 什么都开不了，敏感文件操作**委托 broker 代劳**（broker 校验
//           路径白名单 + 用收敛过的权限 CreateFileW + DuplicateHandle 回传）。
//           —— 主动授予：默认全禁，broker 按策略"发"句柄。
//   形态 B（本模块）：不改 IPC，broker 起 target **之前**，直接给敏感目录的
//           DACL 追加一条针对 target 主体 SID 的 **DENY-WRITE ACE**。于是 target
//           进程自己 CreateFileW(GENERIC_WRITE) 那个目录就会被内核访问检查一票
//           否决（ACCESS_DENIED）。—— 被动剥夺：改客体 ACL，从外部收权。
//
// 【为什么 DENY-ACE 一定能挡住 ALLOW】
//   Windows 访问检查按 ACE 在 DACL 里的顺序逐条评估，**DENY 类型只要命中所需
//   权限位就立即拒绝**，不会再看后面的 ALLOW。系统规范的 ACE 顺序是 DENY 在前、
//   ALLOW 在后（我们用 ACL_REVISION + AddAccessDeniedAceEx 插到最前）。所以哪怕
//   target 的用户 SID 在该目录本来有 Users:(M)(写) 的 ALLOW，追加的 DENY-WRITE
//   也会赢。这就是"改客体 ACL 从外部剥夺权限"的底层依据。
//
// 【最小侵入 + 可回滚】
//   我们只**追加**一条 DENY ACE（不动原有 ACE），并记住加进去了，进程退出/显式
//   调用 RemoveDenyWrite 时把它删掉，避免污染真实目录权限。演示目录建议用临时的
//   C:\sandbox_protected，别拿系统目录做实验。
//
// 【要点】
//   - 目标 SID 默认取"当前进程用户 SID"。因为 M0 的 restricted token 是从当前
//     进程 token 派生的，**用户 SID 不变**（restricted 只是移除 privilege / 加
//     restricting SID），所以对当前用户 SID 下 DENY 就能作用到 target。
//   - DENY ACE 要带 CONTAINER_INHERIT_ACE|OBJECT_INHERIT_ACE，才能覆盖目录下
//     新建的文件（jailbreak-9 写的是目录下的文件）。
// -----------------------------------------------------------------------------
#pragma once

#include <windows.h>

#include <string>
#include <system_error>

namespace sandbox {

class FileAcl {
 public:
    FileAcl() = default;
    ~FileAcl();

    FileAcl(const FileAcl&) = delete;
    FileAcl& operator=(const FileAcl&) = delete;

    // 给 dir 的 DACL 追加一条 DENY-WRITE ACE（含继承标志，覆盖目录内文件）。
    //   sid_string 为空 -> 取当前进程用户 SID（默认，作用到同用户的 target）。
    //   非空 -> 用指定 SID 字符串（如 AppContainer Package SID / 具体用户 SID）。
    // 成功后记录 dir + sid，析构或 RemoveDenyWrite 时可回滚。
    std::error_code AddDenyWrite(const std::wstring& dir, const std::wstring& sid_string = L"");

    // 回滚：把之前 AddDenyWrite 追加的那条 DENY ACE 从 dir 的 DACL 里删掉。
    std::error_code RemoveDenyWrite();

 private:
    bool applied_ = false;
    std::wstring dir_;
    // 保存 SID 的二进制副本，回滚时按值匹配删除对应 DENY ACE。
    std::wstring sid_string_;
};

}  // namespace sandbox
