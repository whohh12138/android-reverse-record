# com.moutai.mall分析

当前手机pixel7a，kernel su root，启动com.moutai.mall卡死，红米note11tpro未有任何异常环境可正常启动。可能存在root检测

---

1. 启动链
    - ContentProvider
    - Application.attachBaseContext/onCreate
    - 首个 Activity.onCreate
    - 各安全、风控、设备指纹 SDK 的初始化

2. 卡死时线程状态
    - 主线程是否卡在 futex、锁、网络请求、JNI 或完整性校验
    - 是否产生 ANR、Java/native 崩溃或主动退出

3. native 库加载链
    - 异常前最后加载的 so
    - 该 so 的 .init_array、JNI_OnLoad
    - dlopen/android_dlopen_ext 后立即执行的初始化函数

4. Root/KernelSU 检测点
    - su、KernelSU 管理器包
    - mount/overlay 痕迹
    - /proc/self/mountinfo、/proc/mounts
    - 系统属性、Bootloader、SELinux、test-keys
    - native 中的 open/access/stat/readlink/__system_property_get

5. Frida 检测
    - 仅当关闭 Frida 可启动、开启后才异常时再看
    - /proc/self/maps、线程名、端口、Unix socket、frida-agent、TracerPid

6. 设备完整性
    - Play Integrity/硬件证明
    - Bootloader 解锁状态
    - KeyStore attestation
    - 服务端风控返回或初始化接口等待

---

## 定位崩溃点

一般在so中检测，hook dlopen。hook call_constructors。

```text
android_dlopen_ext
    ├─ 映射、重定位 so
    ├─ call_constructors
    │   ├─ 依赖 so 的 constructor
    │   ├─ DT_INIT
    │   └─ DT_INIT_ARRAY
    └─ android_dlopen_ext 返回
         ↓
  ART dlsym(handle, "JNI_OnLoad")
         ↓
  调用 JNI_OnLoad
```

- 单纯调用 dlopen，linker 不会自动查找 JNI_OnLoad。
- 使用 System.loadLibrary 时，正常 ART 流程会在 dlopen 成功后查找 JNI_OnLoad : dlsym(handle, "JNI_OnLoad")
- 如果没有该符号，ART 将其视为正常情况。
- NativeBridge 或自定义壳可能自己解析 ELF，不经过 libc dlsym。

libDexHelper.so的android_dlopen_ext、call_constructors有进入退出

libDexHelper.so的android_dlopen_ext退出之后没有其他so dlopen

---

该 so 的节表经过处理，不能依赖 .init_array Section，应以：PT_DYNAMIC + 动态重定位表 DT_RELA 为准

init_array的函数地址：`0x4780`

---

0x4780 大概率是自定义linker，从某个switch case结构看出。

| case | ELF Tag | 代码含义 |
|---:|---|---|
| 2 | DT_PLTRELSZ | PLT 重定位表字节数 |
| 4 | DT_HASH | SysV Hash 表 |
| 5 | DT_STRTAB | 动态字符串表 |
| 6 | DT_SYMTAB | 动态符号表 |
| 7 | DT_RELA | RELA 重定位表 |
| 8 | DT_RELASZ | RELA 表总字节数 |
| 0xC | DT_INIT | 单个初始化函数 |
| 0x11 | DT_REL | REL 重定位表 |
| 0x12 | DT_RELSZ | REL 表总字节数 |
| 0x17 | DT_JMPREL | PLT 重定位表地址 |
| 0x19 | DT_INIT_ARRAY | init_array 数组地址 |
| 0x1B | DT_INIT_ARRAYSZ | init_array 总字节数 |

linker过程：

```text
解析 PT_DYNAMIC
  → 取得 DT_INIT/DT_INIT_ARRAY
  → 应用 DT_RELA/DT_REL/DT_RELR
  → 执行 DT_INIT
  → 依次执行 DT_INIT_ARRAY
```

---

按照loadable segment来修复section header table。参考[so修复.md](moutai/参考/so修复.md)

---

反编译->函数结构->猜功能 | stackplz辅助猜测函数功能  ——>  自定义linker。参考[自定义linker.md](moutai/参考/自定义linker.md)

---

数据源解密 | 内存dump ——> 内嵌so；在自定义linker mmap预留PT_LOAD加载空间时，记录最小装载地址、长度、实际装载地址（mmap返回），在重定位完成INIT调用之前dump 实际装载地址 + len 一整块内存，然后Sofixer修复，获取内嵌匿名so。踩坑：`adb shell su -c cat source.so > dest.so`，导致 原始 LF (0x0A) 被写成 CRLF (0x0D 0x0A)，导致so解析异常。Sofixer修复符号表错位，AI辅助修复。

---

1. 静态定位（检查 JNI_OnLoad、.init_array、字符串表、导入表、）
2. 从退出、报错或上报位置反向找最终判定函数（PC为不存在地址、是否阻塞主线程）
3. hook|观测 常用检测点（线程pthread_create、SVC、fork）

```text
JNI_OnLoad -> sub_1AD84 | sub_1E33C(dexFile) -> sub_3A178(crc32|kill|/proc/%d/fd/%d)
string表 -> magisk|frida|gadget|/proc/%d/fd/%d|
import -> pthread_create|crc32|ptrace|strstr|exit|kill|connect|__system_property_get|access|stat|socket|connect   inflate|deflate
汇编 -> svc (openat|kill)
```

---

## frida检测：

crash崩溃，pc固定地址imm，查看汇编定位`mov reg,imm;br reg`。下面这些地址可能是崩溃点，ida里面查看并xref，引用到JNI_OnLoad里面的，都可能是检测点

imm:{addr}

| imm | addr |
|---|---|
| 0x1f0 | 0x1c018,0x34c6c,0x5a348 |
| 0x1f4 | 0x4bb2c,0x4bbec,0x58914,0x58bfc |
| 0x1f8 | 0x395b4,0x547a0,0x580b0,0x599b0 |
| 0x1fc | 0x49b74,0x49ec8,0x4a57c,0x4b71c |
| 0x2ec | 0x668a4 |
| 0x3d8 | 0x4e90c,0x5f164 |
| 0x3dc | 0x4e884,0x4f8e4,0x50244,0x50698 |
| 0x4cc | 0x4d9f0,0x4e38c,0x5e520 |
| 0x5bc | 0x66e78,0x674f4 |
| 0x61c | 0x6209c |
| 0x6ac | 0x6021c,0x61768 |
| 0x79c | 0x1df98,0x321f0,0x32730 |
| 0x88c | 0x4c408,0x4c66c,0x4cd28,0x543d4 |
| 0x974 | 0x6bfcc |
| 0x978 | 0x1b670,0x48060,0x48e90 |
| 0x97c | 0x47cb8,0x47d50,0x54024 |
| 0xa6c | 0x517c8,0x52724,0x5481c |
| 0xa88 | 0x25fb8 |
| 0xa90 | 0x6f48c,0x6fc5c,0x703b0,0x73968 |
| 0xa94 | 0x72b30,0x732f8,0x7415c |
| 0xa98 | 0x74788 |
| 0xaa0 | 0x25a14,0x73d6c |
| 0xb4c | 0x1f9b4,0x26534,0x26bf0 |
| 0xc3c | 0x63560,0x635d4 |
| 0xd2c | 0x643a0 |
| 0xe1c | 0x3952c,0x69f54 |
| 0xf18 | 0x6b5cc |
| 0xf1c | 0x648f8,0x66170,0x6aa10,0x6af10 |
| 0x11dc | 0x1e598,0x1e6a4 |
| 0x8a68 | 0x1b2a8,0x1b428,0x1b588 |
| 0x8a6c | 0x1b144 |

---

hook常用检测：

pthread_create|fork:

```text
inner_so -> JNI_OnLoad onEnter
[+] fork onEnter caller: +0x1ae40
[+] fork onLeave parent: child_pid=17688 caller=+0x1ae40
[+] clone thread func: +0x302b0
[+] clone thread func: +0x348a4
[+] clone thread func: +0x52b08
[+] clone thread func: +0x4741c
[+] fork onEnter caller: +0x1eaf0
[+] fork onLeave parent: child_pid=17694 caller=+0x1eaf0
[+] clone thread func: +0x6057c
[+] clone thread func: +0x60e1c
[+] clone thread func: +0x6eff0
inner_so -> JNI_OnLoad onLeave
```

| 0x1f0 | 0x34C6C | sub_348A4，大小 0x6E0 |
|---|---|---|
| 0x6ac | 0x61768 | sub_60E1C，大小 0x1058 |
| 0xa90 | 0x6F48C | sub_6EFF0，大小 0x240C |
| 0xa90 | 0x6FC5C | sub_6EFF0 |
| 0xa90 | 0x703B0 | sub_6EFF0 |

---

1e33c检测frida、1ad84检测frida、1e33c加载dex，关键点patch

```javascript
const PATCHES = [
    {
        offset: 0x1ae3c,
        expected: [0xa1, 0xd0, 0xff, 0x97], // bl fork
        replacement: [0x00, 0x00, 0x80, 0x12], // mov w0, #-1
        name: "forked security monitor"
    },
    {
        offset: 0x1eabc,
        expected: [0xe5, 0xc0, 0xff, 0x97], // bl getpid
        replacement: [0xf5, 0x00, 0x00, 0x14], // b +0x3d4
        name: "pipe/ptrace watchdog"
    },
    {
        offset: 0x20f44,
        expected: [0x1c, 0x18, 0x00, 0x34], // cbz w28, +0x300
        replacement: [0x1f, 0x20, 0x03, 0xd5], // nop
        name: "Frida thread scan"
    },
    {
        offset: 0x47cac,
        expected: [0xa8, 0x08, 0x00, 0x37], // tbnz w8, #0, +0x114
        replacement: [0x45, 0x00, 0x00, 0x14], // b +0x114
        name: "Frida ART symbol crash"
    },
    {
        offset: 0x47d44,
        expected: [0xa8, 0x1c, 0x00, 0x37], // tbnz w8, #0, +0x394
        replacement: [0xe5, 0x00, 0x00, 0x14], // b +0x394
        name: "Frida runtime crash"
    },
    {
        offset: 0x54018,
        expected: [0x2a, 0x05, 0x00, 0x37], // tbnz w10, #0, +0xa4
        replacement: [0x29, 0x00, 0x00, 0x14], // b +0xa4
        name: "Frida/root/hook callback crash"
    }
];
```

---

0x25F68处脱壳 -> 参考[dex_load.md](moutai/参考/dex_load.md)和[sub_1E33C_dex_flow.c](moutai/sub_1E33C_dex_flow.c)

---

reqable结合r0capture抓包

参数都是Java层生成，参考[order_flow.py](moutai/order_flow.py)，下单流程
