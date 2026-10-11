> 当前：原始 `libDexHelper.so` / 已依据原文件的 PT_LOAD + PT_DYNAMIC 重建 19 个 Section Header / 备份保留在 `libDexHelper.so.bak`

## 一、修复原则

没有把 libDexHelper.memory.fixed.so 的 Section Header 原样复制回来。

原因是内存 Dump 中：

- sh_offset 基本等于运行时 VA，不适用于原始文件布局。
- .init_array 已经完成重定位。
- .dynsym/.dynstr/.hash 已被自定义 linker 写入 payload 的符号信息。
- SoFixer 对部分 Section 边界是按相邻区域猜测的。

例如 SoFixer 文件中：

```text
.rela.plt size = 0x360    实际 DT_PLTRELSZ = 0x240
.dynsym size   = 0x2000   原外壳有效符号只有 35×24 = 0x348
.hash size     = 0xd90    实际表大小 = 0x6c8
```

所以实际做法是：

- SoFixer 文件：仅作为 Section 类型和总体布局参考
- 原始文件：保留全部代码、数据、动态表和全局值
- PT_LOAD：计算 VA 到原文件偏移
- PT_DYNAMIC：确定动态 Section 的地址和大小
- 原始 .shstrtab：恢复 Section 名称
- 反汇编及 EH Frame：确定 .plt/.text/.rodata 边界

---

## 二、先备份

修复前先复制：

原始备份：
`/mnt/d/go/ai/workspace3/libDexHelper.so.bak`

SHA-256：
`ce261ae60d93a039839ef403dd4955f765af2d348625c8b79325a023c14c43bc`

修复后的文件仍是：

`/mnt/d/go/ai/workspace3/libDexHelper.so`

SHA-256：
`2a06d7bb41a443afe3561d0eb23e2c559480f840c538201e74df2e5eed9f06fe`

---

## 三、读取 ELF Header

原文件以下字段本身是正常的：

```text
e_entry     = 0x2b10
e_phoff     = 0x40
e_phnum     = 8
e_shoff     = 0x12c6d0
e_shentsize = 0x40
e_shnum     = 19
e_shstrndx  = 18
```

因此不需要移动 Section Header Table，只需要重写：

`0x12c6d0 ～ 0x12cb90`

也就是：

19 × 0x40 = `0x4c0` 字节

每项为：

```c
typedef struct {
    Elf64_Word  sh_name;
    Elf64_Word  sh_type;
    Elf64_Xword sh_flags;
    Elf64_Addr  sh_addr;
    Elf64_Off   sh_offset;
    Elf64_Xword sh_size;
    Elf64_Word  sh_link;
    Elf64_Word  sh_info;
    Elf64_Xword sh_addralign;
    Elf64_Xword sh_entsize;
} Elf64_Shdr;
```

---

## 四、根据 PT_LOAD 建立 VA→文件偏移映射

原文件有四个 PT_LOAD：

| LOAD | 文件偏移 | VA | FileSz | MemSz | 权限 |
|---|---:|---:|---:|---:|:---:|
| 0 | 0x0 | 0x0 | 0x4ca0 | 0x4ca0 | R-X |
| 1 | 0x4d08 | 0x14d08 | 0x320 | 0x388 | RW- |
| 2 | 0x6000 | 0x26000 | 0x1000 | 0x1000 | RW- |
| 3 | 0x7000 | 0x47000 | 0x1256d0 | 0x1256d0 | RW- |

Section 位于某个 PT_LOAD 内时：

```text
sh_offset = p_offset + (sh_addr - p_vaddr)
```

例如：

```text
.init_array:
0x4d08 + (0x14d08 - 0x14d08)
= 0x4d08

.dynamic:
0x6000 + (0x26000 - 0x26000)
= 0x6000

.dynsym:
0x7000 + (0x169000 - 0x47000)
= 0x129000

.dynstr:
0x7000 + (0x16b000 - 0x47000)
= 0x12b000

.hash:
0x7000 + (0x16c000 - 0x47000)
= 0x12c000
```

这一步解决了内存 Dump 中 sh_offset=VA 不能直接用于磁盘文件的问题。

---

## 五、解析 PT_DYNAMIC

原始动态表位于：

```text
PT_DYNAMIC:
VA     = 0x26000
Offset = 0x6000
```

关键项：

```text
DT_INIT_ARRAY     = 0x14d08
DT_INIT_ARRAYSZ   = 0x10
DT_FINI_ARRAY     = 0x14d18
DT_FINI_ARRAYSZ   = 0x10

DT_HASH           = 0x16c000
DT_STRTAB         = 0x16b000
DT_STRSZ          = 0x877
DT_SYMTAB         = 0x169000
DT_SYMENT         = 0x18

DT_PLTGOT         = 0x14f18

DT_RELA           = 0x26e8
DT_RELASZ         = 0x48
DT_RELAENT        = 0x18

DT_JMPREL         = 0x2730
DT_PLTRELSZ       = 0x240
DT_PLTREL         = DT_RELA
```

动态表共 29 项，包括最后一个 DT_NULL：

29 × 16 = `0x1d0`

所以 .dynamic 的真实 Section 大小使用 `0x1d0`，而不是整个 PT_DYNAMIC 的 `0x1000` 填充区。

---

## 六、恢复 Section 名称

原始 .shstrtab 没有损坏：

```text
Offset = 0x504d
Size   = 0x95
```

里面仍然包含：

```text
.eh_frame_hdr
.fini_array
.init_array
.shstrtab
.eh_frame
.rela.plt
.rela.dyn
.comment
.dynamic
.rodata
.dynstr
.dynsym
.data
.text
.hash
.bss
.got
```

所以直接重新填写每项的 sh_name 偏移，不需要新建字符串表。

---

## 七、逐个重建 Section Header

### 0. NULL Section

```text
Name   = ""
Type   = SHT_NULL
```

其他字段全部为 0

这是 ELF Section Table 的固定第 0 项。

### 1. .hash

来源：

```text
DT_HASH = 0x16c000
```

VA 转文件偏移：

```text
0x7000 + (0x16c000 - 0x47000)
= 0x12c000
```

SysV Hash 头部：

```text
nbucket = 197
nchain  = 235
```

大小公式：

```text
(2 + nbucket + nchain) × 4
= (2 + 197 + 235) × 4
= 0x6c8
```

最终：

```text
Type      = SHT_HASH
Flags     = SHF_ALLOC
Address   = 0x16c000
Offset    = 0x12c000
Size      = 0x6c8
Link      = 2        // .dynsym
Alignment = 4
EntSize   = 4
```

### 2. .dynsym

来源：

```text
DT_SYMTAB = 0x169000
DT_SYMENT = 0x18
```

映射：

```text
VA     = 0x169000
Offset = 0x129000
```

原文件预留了 235 个符号槽，但实际外壳重定位引用的最大符号索引为：

最大索引 = 34

所以有效外壳符号数为：

34 + 1 = 35

第 35～234 项全部是零预留槽，不纳入 Section，否则 IDA 会把预留槽识别成大量异常全局符号。

大小：

35 × 0x18 = `0x348`

前 3 项是：

```text
0：空符号
1：LOCAL SECTION .text
2：LOCAL SECTION .data
```

所以：

sh_info = 3

最终：

```text
Type      = SHT_DYNSYM
Flags     = SHF_ALLOC
Address   = 0x169000
Offset    = 0x129000
Size      = 0x348
Link      = 3        // .dynstr
Info      = 3        // 第一个 GLOBAL 符号
Alignment = 8
EntSize   = 0x18
```

### 3. .dynstr

来源：

```text
DT_STRTAB = 0x16b000
DT_STRSZ  = 0x877
```

映射：

```text
Offset = 0x7000 + (0x16b000 - 0x47000)
       = 0x12b000
```

最终：

```text
Type      = SHT_STRTAB
Flags     = SHF_ALLOC
Address   = 0x16b000
Offset    = 0x12b000
Size      = 0x877
Alignment = 1
```

恢复后重定位符号可以正常显示为：

```text
dlerror
fgets
memcpy
mmap
dlopen
dlsym
fopen
pread
mprotect
close
...
```

而不是内存 Dump 中 payload 的符号。

### 4. .rela.dyn

来源：

```text
DT_RELA    = 0x26e8
DT_RELASZ  = 0x48
DT_RELAENT = 0x18
```

它位于第一个 PT_LOAD，该段 VA 和文件偏移相同。

最终：

```text
Type      = SHT_RELA
Flags     = SHF_ALLOC
Address   = 0x26e8
Offset    = 0x26e8
Size      = 0x48
Link      = 2        // .dynsym
Info      = 0
Alignment = 8
EntSize   = 0x18
```

共：

0x48 / 0x18 = 3 条重定位

### 5. .rela.plt

来源：

```text
DT_JMPREL   = 0x2730
DT_PLTRELSZ = 0x240
DT_RELAENT  = 0x18
```

最终：

```text
Type      = SHT_RELA
Flags     = SHF_ALLOC
Address   = 0x2730
Offset    = 0x2730
Size      = 0x240
Link      = 2        // .dynsym
Info      = 14       // .got
Alignment = 8
EntSize   = 0x18
```

共：

0x240 / 0x18 = 24 条 PLT 重定位

SoFixer 误写成了 0x360，导致 0x2970 之后的 AArch64 PLT 指令被当成重定位项。

### 6. .plt

.rela.plt 结束位置：

`0x2730 + 0x240` = `0x2970`

AArch64 PLT：

```text
PLT0       = 0x20
每个 PLT项 = 0x10
重定位数量  = 24
```

所以：

```text
Size = 0x20 + 24 × 0x10
     = 0x1a0
```

结束位置：

`0x2970 + 0x1a0` = `0x2b10`

正好等于 ELF Entry：

e_entry = `0x2b10`

最终：

```text
Type      = SHT_PROGBITS
Flags     = SHF_ALLOC | SHF_EXECINSTR
Address   = 0x2970
Offset    = 0x2970
Size      = 0x1a0
Alignment = 0x10
EntSize   = 0x10
```

### 7. .text

开始位置来自：

```text
.plt 结束 = 0x2b10
e_entry   = 0x2b10
```

.eh_frame_hdr 还给出了 7 个带 unwind 信息的函数：

```text
0x2b1c
0x2bf8
0x2cd0
0x303c
0x3184
0x33f8
0x4780
```

最后一段代码结束后，0x49a0 开始出现只读表和字符串，所以：

```text
Address = 0x2b10
Offset  = 0x2b10
End     = 0x49a0
Size    = 0x49a0 - 0x2b10
        = 0x1e90
```

最终：

```text
Type      = SHT_PROGBITS
Flags     = SHF_ALLOC | SHF_EXECINSTR
Address   = 0x2b10
Offset    = 0x2b10
Size      = 0x1e90
Alignment = 4
```

sub_33F8 完整落在该 Section 中。

### 8. .rodata

从代码结束处开始：

Start = `0x49a0`

到 PT_GNU_EH_FRAME 开始：

End = `0x4a70`

大小：

`0x4a70 - 0x49a0` = `0xd0`

该区域包含：

```text
JNI_OnLoad
/proc/self/maps
%lx-%lx ...
libc.so
sscanf
```

最终：

```text
Type      = SHT_PROGBITS
Flags     = SHF_ALLOC
Address   = 0x49a0
Offset    = 0x49a0
Size      = 0xd0
Alignment = 8
```

### 9. .eh_frame_hdr

直接来自 PT_GNU_EH_FRAME：

```text
Address = 0x4a70
Offset  = 0x4a70
Size    = 0x44
```

最终：

```text
Type      = SHT_PROGBITS
Flags     = SHF_ALLOC
Address   = 0x4a70
Offset    = 0x4a70
Size      = 0x44
Alignment = 4
```

### 10. .eh_frame

.eh_frame_hdr 编码：

```text
version        = 1
eh_frame_ptr   = DW_EH_PE_pcrel | DW_EH_PE_sdata4
相对值         = 0x44
字段位置       = 0x4a74
```

因此：

`0x4a74 + 0x44` = `0x4ab8`

第一个可执行 PT_LOAD 在：

`0x4ca0`

结束，所以：

```text
Address = 0x4ab8
Offset  = 0x4ab8
Size    = 0x4ca0 - 0x4ab8
        = 0x1e8
```

最终：

```text
Type      = SHT_PROGBITS
Flags     = SHF_ALLOC
Address   = 0x4ab8
Offset    = 0x4ab8
Size      = 0x1e8
Alignment = 8
```

### 11. .init_array

来源：

```text
DT_INIT_ARRAY   = 0x14d08
DT_INIT_ARRAYSZ = 0x10
```

映射：

Offset = `0x4d08`

最终：

```text
Type      = SHT_INIT_ARRAY
Flags     = SHF_ALLOC | SHF_WRITE
Address   = 0x14d08
Offset    = 0x4d08
Size      = 0x10
Alignment = 8
EntSize   = 8
```

两个槽位：

```text
slot 0 → 重定位后为 0x4780
slot 1 → 0
```

这里只恢复 Section 描述，不把内存中的绝对地址写回原文件。

### 12. .fini_array

来源：

```text
DT_FINI_ARRAY   = 0x14d18
DT_FINI_ARRAYSZ = 0x10
```

映射：

Offset = `0x4d18`

最终：

```text
Type      = SHT_FINI_ARRAY
Flags     = SHF_ALLOC | SHF_WRITE
Address   = 0x14d18
Offset    = 0x4d18
Size      = 0x10
Alignment = 8
EntSize   = 8
```

### 13. .dynamic

来自 PT_DYNAMIC：

```text
Address = 0x26000
Offset  = 0x6000
```

实际有效表到第一个 DT_NULL：

29 × 16 = `0x1d0`

最终：

```text
Type      = SHT_DYNAMIC
Flags     = SHF_ALLOC | SHF_WRITE
Address   = 0x26000
Offset    = 0x6000
Size      = 0x1d0
Link      = 3        // .dynstr
Alignment = 8
EntSize   = 0x10
```

### 14. .got

开始位置：

DT_PLTGOT = `0x14f18`

重定位目标覆盖：

`0x14f30 ～ 0x14ff8`

最后一个 8 字节槽结束于：

`0x15000`

因此：

```text
Address = 0x14f18
Offset  = 0x4f18
Size    = 0x15000 - 0x14f18
        = 0xe8
```

最终：

```text
Type      = SHT_PROGBITS
Flags     = SHF_ALLOC | SHF_WRITE
Address   = 0x14f18
Offset    = 0x4f18
Size      = 0xe8
Alignment = 8
EntSize   = 8
```

### 15. .data

第二个 PT_LOAD 的文件内容结束于：

```text
VA = 0x14d08 + 0x320
   = 0x15028
```

.got 结束于：

`0x15000`

所以：

```text
Address = 0x15000
Offset  = 0x5000
Size    = 0x15028 - 0x15000
        = 0x28
```

最终：

```text
Type      = SHT_PROGBITS
Flags     = SHF_ALLOC | SHF_WRITE
Address   = 0x15000
Offset    = 0x5000
Size      = 0x28
Alignment = 8
```

### 16. .bss

第二个 PT_LOAD：

```text
FileSz = 0x320
MemSz  = 0x388
```

差值：

`0x388 - 0x320` = `0x68`

所以：

```text
Address = 0x15028
Offset  = 0x5028
Size    = 0x68
```

最终：

```text
Type      = SHT_NOBITS
Flags     = SHF_ALLOC | SHF_WRITE
Address   = 0x15028
Offset    = 0x5028
Size      = 0x68
Alignment = 8
```

SHT_NOBITS 不实际占用文件数据。

### 17. .comment

文件偏移：

```text
0x5028 ～ 0x504d
Size = 0x25
```

内容：

```text
GCC: (GNU) 4.9 20140514 (prerelease)
```

最终：

```text
Type      = SHT_PROGBITS
Flags     = SHF_MERGE | SHF_STRINGS
Address   = 0
Offset    = 0x5028
Size      = 0x25
Alignment = 1
EntSize   = 1
```

它不是运行时必要 Section，但原始数据完整，因此一并恢复。

### 18. .shstrtab

原文件本来就是完整的：

```text
Address = 0
Offset  = 0x504d
Size    = 0x95
```

最终：

```text
Type      = SHT_STRTAB
Flags     = 0
Address   = 0
Offset    = 0x504d
Size      = 0x95
Alignment = 1
```

并保持：

e_shstrndx = 18

---

## 八、为什么没有给巨大加密区创建 Section

第四个 PT_LOAD 覆盖：

VA `0x47000 ～ 0x16c6d0`

其中大部分是：

- 加密 payload
- 自定义 linker 使用的数据
- 预留的符号表覆盖区域

它不需要强行标记成 .data。

Section 并不要求覆盖所有 Segment 字节。给整个区域创建 .data 反而可能让 IDA 生成大量错误全局变量。

只给其中能够通过 PT_DYNAMIC 确定的尾部表建立 Section：

- .dynsym
- .dynstr
- .hash

剩余部分仍由 PT_LOAD Segment 映射，IDA 中仍然可以查看。

---

## 九、实际写入方式

19 个 Elf64_Shdr 重新构造后，依次写到：

```text
e_shoff + index × e_shentsize
= 0x12c6d0 + index × 0x40
```

等价逻辑：

```python
struct.pack_into(
    "<IIQQQQIIQQ",
    elf,
    0x12c6d0 + index * 0x40,
    sh_name,
    sh_type,
    sh_flags,
    sh_addr,
    sh_offset,
    sh_size,
    sh_link,
    sh_info,
    sh_addralign,
    sh_entsize,
)
```

没有修改：

- ELF Header
- Program Header
- 动态表
- 重定位内容
- 代码
- 原始全局数据
- 加密 payload

文件大小也没有变化。

实际差异：

```text
只修改范围：0x12c6d0 ～ 0x12cb90
实际改变字节：98
该范围之前：完全一致
该范围之后：完全一致
```

---

## 十、验证结果

修复前 readelf Warning/Error：32

修复后 readelf Warning/Error：0

修复后：

- 24 条 .rela.plt 全部能解析出正确导入名。
- 3 条 .rela.dyn 正常。
- .dynsym 正确显示 35 个外壳符号。
- .text 正确覆盖 sub_33F8。
- Section 与 PT_LOAD 映射一致。
- 原始代码和全局数据未被内存 Dump 内容替换。
