# demo.so DEX 加载与方法体回填分块说明

## 最终结论

`demo.so::sub_1E33C` 使用原 `base.apk` 对应 `DexFile.mCookie` 找到五个 ART DexFile/DEX 映射，先修复每个 DEX 最多 `0x20000` 字节的头部和索引区，再通过 `makeInMemoryDexElements` 触发 ART 建立新 DexFile，合并并替换 cookie，最后把真实 `code_item` 地址换算成 DEX 相对偏移，以 ULEB128 回填全部 `class_data.code_off`。

最终 dump 点是 `demo.so+0x25F68`：此时五个 DEX 的 `code_off` 回填已经结束，`sub_1E33C` 尚未返回。

## DEX 输出

| DEX | 完整大小 | 修复后 SHA256 | 方法记录 | 回填 code_off | 有效 code_item | 非法 code_item |
|---|---:|---|---:|---:|---:|---:|
| classes1.dex | 15,641,684 | `CA086C384845786171B8C893F3E708B38C8BD20AA610CE6A1DB03320C23C4908` | 57,795 | 16,237 | 55,220 | 0 |
| classes2.dex | 12,292,687 | `DF9344EC1A50DC909E1455D4DA03869E5AD4B390899C63B3159E0242F0747EBD` | 57,666 | 8,814 | 55,290 | 0 |
| classes3.dex | 13,898,315 | `F55DAB50339123DF4DCECACBB02392DFA4C413002FD2845B4214DB90C6DF520F` | 58,237 | 12,691 | 55,505 | 0 |
| classes4.dex | 2,411,019 | `CE7A2FC121BEFC8C752B8940C9BFC0C2E3AE69FCB8F227B586ACF1F22C080175` | 10,283 | 2,249 | 9,649 | 0 |
| classes5.dex | 433,643 | `A4BAB9F2AF4331EFB586356C6447A7222742643017D0CA0C858F9395E48264F1` | 1,621 | 424 | 1,496 | 0 |
| 合计 | 44,677,348 | — | 185,602 | 40,415 | 177,160 | 0 |

五个运行时 DEX 的 `file_size` 与 `moutai3/class1.dex..class5.dex` 逐一相同，因此 `x26=0..4` 到 `classes1.dex..classes5.dex` 的映射已由头部大小核对。

---

## 块 1：定位 base.apk 对应的 DexFile

**地址：** `demo.so+0x21BD8..+0x21CCC`

**输入：** Java 类加载器的 `DexPathList.dexElements`。

**作用：** 遍历 Element，读取 `path`，筛选路径末尾为 `base.apk` 的元素，随后取得其 `dexFile`。

**输出：** Java `dalvik.system.DexFile` 对象。

**关键汇编：**

```asm
+0x21BF0  blr x8    ; GetFieldID("path", "Ljava/io/File;")
+0x21C08  blr x8    ; GetObjectField(element, path)
+0x21C30  blr x8    ; GetFieldID("path", "Ljava/lang/String;")
+0x21C48  blr x8    ; GetObjectField(file, pathString)
+0x21C64  blr x8    ; GetStringUTFChars -> /data/app/.../base.apk
+0x21CCC  bl  strncmp
```

**等价关键代码：**

```cpp
for (Element element : classLoader.pathList.dexElements) {
    const char* path = GetStringUTFChars(element.path.path);
    if (ends_with(path, "base.apk")) {
        baseDexFile = element.dexFile;
        break;
    }
}
```

---

## 块 2：读取原 mCookie，取得 ART DexFile 和 DEX 基址

**地址：** `demo.so+0x21D60..+0x21DC4`

**输入：** 上一块得到的 Java `DexFile`。

**作用：** 通过反射读取 `mCookie`，转换为 `long[]`，再从 ART DexFile 对象读取 DEX 映射基址。Android 版本差异通过 cookie 首元素/第二元素选择处理。

**输出：** 五个 DEX 的 ART DexFile 指针、基址、大小及辅助记录。

**关键汇编：**

```asm
+0x21D60  blr x8          ; GetFieldID("mCookie", "Ljava/lang/Object;")
+0x21D78  blr x8          ; GetObjectField(dexFile, mCookie)
+0x21D94  blr x8          ; GetLongArrayElements(cookie)
+0x21D98  add x8, x0, #8 ; 某些 Android 版本跳过 cookie[0]
+0x21DA0  csel x8, x0, x8, eq
+0x21DA4  ldr x8, [x8]   ; ART DexFile*
+0x21DB4  ldr x22, [x8,#8] ; DEX begin
```

**等价关键代码：**

```cpp
jlong* cookie = GetLongArrayElements(dexFile.mCookie);
art::DexFile* artDex = reinterpret_cast<art::DexFile*>(cookie[cookieIndex]);
uint8_t* dexBegin = artDex->begin_;
```

---

## 块 3：逐个修复 DEX 头部和索引区

**地址：** `demo.so+0x22988..+0x22A9C`，循环五次。

**输入：** `x20=DEX 目标映射`、加密源数据、每个 DEX 的 `file_size`。

**作用：** 将处理长度限制为 `min(file_size, 0x20000)`，初始化 `0x80` 字节密钥状态，以 16 字节为单位解密，然后复制回原 DEX 映射。这里不直接复制完整方法体；它只让 ART 能读取 header、ID 表、class_def 等前部结构。

**输出：** 五个头部可解析、方法 `code_off` 尚为占位值的 DEX 映射。

**关键汇编：**

```asm
+0x22A14  cmp  w8, #0x20000
+0x22A18  mov  w9, #0x20000
+0x22A1C  csel w8, w8, w9, lt       ; len=min(file_size,0x20000)
+0x22A20  mov  w0, #0x80
+0x22A28  bl   malloc                ; key/state
+0x22A38  bl   sub_293E0             ; 初始化密钥
+0x22A5C  and  x8, x19, #~0xf
+0x22A60  add  x0, x20, x8          ; 16-byte encrypted block
+0x22A64  add  x1, x23, x8          ; plaintext destination
+0x22A6C  bl   sub_2952C             ; decrypt16
+0x22A7C  and  x2, x22, #~0xf
+0x22A80  mov  x0, x20              ; DEX mapping destination
+0x22A84  mov  x1, x23              ; plaintext buffer
+0x22A88  bl   memcpy
```

**等价关键代码：**

```cpp
size_t n = std::min(dex_file_size, size_t(0x20000)) & ~size_t(0xF);
init_key(key_state, 0x80);
for (size_t off = 0; off < n; off += 0x10)
    decrypt16(dex_begin + off, plain + off, key_state);
memcpy(dex_begin, plain, n);
```

---

## 块 4：准备 ART 内存加载入口

**地址：** `demo.so+0x22D14..+0x23F90`

**输入：** 已修复前部的五个 DEX、当前类加载器、Android API 版本。

**作用：** 获取 `BaseDexClassLoader.pathList`、`DexPathList`、`Element` 和 `makeInMemoryDexElements` 等类、字段及方法；按系统版本选择签名和 cookie 解释方式。

**输出：** 后续构造内存 Element 所需的 JNI class/method/field ID。

**关键代码：**

```cpp
jclass dexPathList = FindClass("dalvik/system/DexPathList");
jmethodID makeElements = GetStaticMethodID(
    dexPathList,
    "makeInMemoryDexElements",
    "([Ljava/nio/ByteBuffer;Ljava/util/List;)[Ldalvik/system/DexPathList$Element;"
);
```

---

## 块 5：以 DirectByteBuffer 触发 ART 建立五个新 DexFile

**地址：** `demo.so+0x23F94..+0x240A0`，循环五次。

**输入：** 一个固定 `0x11C` 字节的触发缓冲区，以及前面准备的 ART/DexFile 状态。

**作用：** `NewDirectByteBuffer` 在这里包装的是触发缓冲区，不是完整 DEX 映射。随后把单个 ByteBuffer 放进数组，调用 `makeInMemoryDexElements`；加载链中的 native/ART 路径据已保存的五个 DEX 基址和大小建立真实 DexFile，返回 Element。

**输出：** 五个新的 `DexPathList.Element` 及其内部 `DexFile/mCookie`。

**关键汇编：**

```asm
+0x23F98  ldr x8, [x8,#0x728]  ; JNI NewDirectByteBuffer
+0x23FA0  mov w2, #0x11c
+0x23FAC  blr x8                ; NewDirectByteBuffer(trigger,0x11c)
+0x24010  blr x8                ; GetStaticMethodID(makeInMemoryDexElements)
+0x2404C  blr x8                ; NewObjectArray(1, ByteBuffer)
+0x2406C  blr x8                ; SetObjectArrayElement(array,0,buffer)
+0x24084  bl  sub_4031C         ; 调用 makeInMemoryDexElements
+0x240A0  blr x8                ; GetObjectArrayElement(elements,0)
```

**等价关键代码：**

```cpp
jobject trigger = NewDirectByteBuffer(trigger_addr, 0x11C);
jobjectArray buffers = NewObjectArray(1, ByteBufferClass, nullptr);
SetObjectArrayElement(buffers, 0, trigger);
jobjectArray elements = CallStaticObjectMethod(
    DexPathListClass, makeInMemoryDexElements, buffers, nullptr);
jobject newElement = GetObjectArrayElement(elements, 0);
```

---

## 块 6：合并并替换 DexFile.mCookie

**地址：** `demo.so+0x24AE4..+0x24C2C`

**输入：** 原 `mCookie` long[] 和五个新 Element 内的 DexFile 指针。

**作用：** 新建足够大的 `long[]`，复制原 cookie 内容并追加五个新 DexFile 指针，最后写回 Java DexFile 对象。

**输出：** Java/ART 后续类解析可见新的五个 DexFile。

**关键汇编：**

```asm
+0x24ADC  blr x8                ; GetArrayLength(oldCookie)
+0x24AF8  blr x8                ; GetLongArrayElements(oldCookie)
+0x24B18  add w1, w20, w9       ; old_count + new_count
+0x24B20  blr x8                ; NewLongArray
+0x24B3C  blr x8                ; GetLongArrayElements(merged)
...                             ; copy old + append new pointers
+0x24C28  mov x3, x25           ; merged cookie
+0x24C2C  blr x8                ; SetObjectField(dexFile,mCookie,merged)
```

**等价关键代码：**

```cpp
jlongArray merged = NewLongArray(old_count + new_count);
copy_cookie(merged, old_cookie, old_count);
append_new_dex_files(merged, new_dex_files, 5);
SetObjectField(javaDexFile, mCookieField, merged);
```

---

## 块 7：回填全部方法 code_off

**地址：** `demo.so+0x24FB4..+0x25080`

**输入：** 每个方法的真实 `code_item` 绝对地址、所属 DEX 基址、原 class_data 中 code_off 字段位置。

**作用：** 对每个已记录方法计算 `code_item - dex_base`，再以 ULEB128 写回原 `class_data.code_off`。五个 DEX 共执行 40,415 个方法偏移回填。

**输出：** 方法定义指向 DEX 尾部已有的完整 code_item；方法体字节本身不需要再次复制。

**关键汇编：**

```asm
+0x25014  ldr   x20, [x22]       ; method record
+0x25018  ldr   x8, [x20,#8]     ; absolute code_item address
+0x2501C  ldrsw x9, [x20,#0x20]  ; code_off field offset
+0x25020  sub   x8, x8, x21      ; relative code_off=code_item-dex_base
+0x25028  add   x26, x21, x9     ; class_data.code_off address
+0x25040  strb  w11, [x26,x9]    ; ULEB128 continuation bytes
+0x2507C  strb  w8, [x26,w9,uxtw]; final data byte
+0x24FFC  strb  wzr, [x0]        ; five-byte编码的结束字节
```

**等价关键代码：**

```cpp
uint32_t code_off = uint32_t(method.code_item_address - dex_base);
uint8_t* field = dex_base + method.code_off_field_offset;
write_uleb128_fixed_width(field, code_off);
```

`UpgradeUtil.e` 的实测写回：

```text
field: classes3.dex+0x1C94B3
before: ccbacb8100 -> code_off 0x32DD4C
stores: +0x25040(dc,ea,f6), +0x2507C(85), +0x24FFC(00)
after:  dceaf68500 -> code_off 0xBDB55C
```

---

## 块 8：完整 DEX dump 点与头部修复

**地址：** `demo.so+0x25F68`，`sub_1E33C` 返回前。

**输入：** 五个已回填的 DEX 基址和各自 header.file_size。

**作用：** 从内存整体写出五个 DEX；主机端重新计算 DEX SHA-1 signature 和 Adler-32 checksum。

**输出：** `all_dex_dump/classes1_refilled_fixed.dex..classes5_refilled_fixed.dex`。

**关键 Frida 代码：**

```javascript
for (const [index, image] of dexImages) {
    writeMemoryImage(
        `${OUT_DIR}/classes${index + 1}_refilled_before_return.dex`,
        image.base,
        image.base.add(image.fileSize)
    );
}
```

**关键 DEX 头修复代码：**

```python
b[12:32] = hashlib.sha1(b[32:]).digest()
b[8:12] = struct.pack('<I', zlib.adler32(b[12:]) & 0xffffffff)
```

---

## 时序摘要

```text
JNI_OnLoad
  └─ sub_1E33C
      ① 缓存宿主类 → getClassLoader → pathList → dexElements → 找到 base.apk
      ② 读 mCookie → ArtDexFile->begin_（宿主 dex 的内存地址）
      ③ 扫 dex 尾部 fdex 记录表 → 找到 dexdata0
      ④ Zstd 解压 → [描述符表][0x1000头][5个加密dex]
      ⑤ 循环 5 次：
          SM4 解密前 0x20000 写回     （让 ART 认得目录）
          扫 BBbb.dgc 剥壳            （拿到真头部+方法表）
          建方法记录表                 （真字节码地址 + code_off 位置）
      ⑥ 空壳 ByteBuffer 当饵 → makeInMemoryDexElements（借 hook 偷梁换柱）
         → 得到 5 个真 Element
      ⑦ 合并 mCookie：旧项照抄 + 5 个新项追加 → 写回
      ⑧ 嫁接：新 native DexFile->begin_ = 解密 dex 地址
      ⑨ 回填：4 万个 code_off 按 5 字节定宽 ULEB128 写正
      ⑩ free/Release 收尾 + 拉起看门狗线程 → 返回
之后：Java 里 loadClass 任何业务类 → ART 按 mCookie 找到嫁接的 dex → 执行真实代码
```
