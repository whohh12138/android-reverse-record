/* ============================================================================
 * demo.so  sub_1E33C —— DEX 加载/释放流程还原（贴合 IDA 反编译）
 *
 * 来源：dumpdex/demo.so.i64 中 sub_1E33C(0x1E33C, size 0x8C80)
 * 依据 trace_1e33c.log patch 掉死分支后的反编译（decomp_patched.c, 2320 行）
 * —— 仅还原实际执行的 DEX 加载/释放路径；所有 if(X) 均为真实分支。
 *
 * 与 dump_dex.md / dex_loading_blocks.md 的差异（patch 后确认的真相）：
 *   - dlopen helper SO / open+mmap 回退 / classes.jar 回退：死分支，未执行
 *   - 磁盘空壳 open/write/loadDex、Dalvik dvmRawDexFileOpenArray、
 *     ART21-25 OpenMemory、ART26-28 InMemoryDexClassLoader：死分支，未执行
 *   - 真实路径：载荷直接取自 base.apk 内存 DEX 尾部的 fdex 记录
 *
 * JNI 调用反编译中为 (*(vtable+offset)) 形式，此处写为标准 JNI 名，
 * 括号内为 arm64 JNI 函数表偏移。
 * ==========================================================================*/

#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ---- IDA 命名的全局/子函数（保持原样，便于对照） ---- */
extern void   sub_3A178(JNIEnv*, void*);          // 配置结构初始化
extern void   sub_2C744(void* out, ...);          // 字符串解密/拼接 helper
extern void*  sub_12F00(void* out, int, int, const char* fmt, ...); // snprintf 变体
extern int    sub_102CC(char* buf, size_t, const char* fmt, ...);   // snprintf
extern void*  sub_13DC0(JNIEnv*, jobject obj, jmethodID getClassLoader); // CallObjectMethod 包装
extern void*  sub_2C31C(JNIEnv*, jclass, jmethodID);   // CallStaticObjectMethod 包装(0x388 之后手动传参)
extern void*  sub_C9C00(size_t);                  // malloc + memset 0 的分配器
extern void*  sub_6CC5C(void* vec, void* item);   // vector push_back(扩容)
extern void*  sub_6CE4C(void* dst_vec, void* src_vec); // vector 合并/转移
extern void   sub_6C9A8(void* rec, uint32_t len); // 读记录头大端长度字段
extern void*  sub_6CB50(void* rec);               // 解记录包封+Zstd 解压(内部 sub_8B848) → 载荷
extern void*  sub_6C760(const void* dex, uint32_t dex_size, void* out_rec, void* out_len);
                                                  // 校验 DEX magic，扫尾部 fdex 记录表找 dexdata0
extern void   sub_293E0(const uint8_t key16[16], void* roundkeys_0x80); // SM4 32 轮密钥
extern void   sub_2952C(const void* in16, void* out16, const void* roundkeys); // SM4-ECB 解密一块
extern void   sub_10380(uint8_t buf24[24]);       // {begin,len} 打包成 1 个 jlong cookie 值 → buf[16..23]
extern void*  sub_6EFF0(void*);                   // 看门狗线程例程

/* ---- 关键全局（IDA 名） ---- */
extern unsigned char  qword_120090[284];   // 284B 空壳 DEX(仅 LEmpty;)，喂给 ByteBuffer 的"饵"
extern uint32_t qword_1298A8;              // DEX 数量
extern void**   qword_1298B8;              // DEX 指针表(指向解压载荷内的各 DEX)
extern uint32_t* qword_1298B0;             // DEX 长度表
extern uint8_t  qword_129580;              // 就绪标志
extern void*    qword_129588;              // SM4 密钥材料(16B, 运行中解出)
extern void**   off_1263E8;                // 配置块(+16: DEX 数量; +64: 字符串; +183*8...)
extern void***  off_11FC70;                // 每个真实 DEX 的记录 vector(vector<vector<rec>>)

void sub_1E33C(JNIEnv *env)
{
  /* ================================================================
   * 阶段 0  环境初始化与对抗(0x1E33C~0x21740) —— 与 DEX 流程无直接关系
   *   配置块解密(sub_3A178)、RegisterNatives、GetJavaVM、
   *   fork 安全监控子进程(pipe+fork+pthread)、/proc 扫描反调试、
   *   三段解密字符串(SIMD: buf[i] += ~(i%3) 变换; 尾部 XOR 0xAC)
   *   ================================================================ */
  sub_3A178(env, *off_1263E8 /* 原名 off_11FDC0[0] */);
  /* ... 反调试/看门狗初始化(略，见 decomp_patched.c L528-L1417) ... */

  /* ================================================================
   * 阶段 1  探测 DexCache 并在 base.apk 内存 DEX 中定位 dexdata0 载荷
   *   (0x1419~0x1500 对应 0x215EC~0x21764 / 0x21BD8~0x22204)
   * ================================================================ */
  jobject   classObj = (jobject)(*(void**)(*off_1263E8 + 44));
  jclass    clazz    = (*env)->FindClass(env, "java/lang/Class");            // +0x30
  (*env)->GetFieldID(env, clazz, "dexCache", "Ljava/lang/DexCache;");      // 试 A 类型
  if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); }        // +0x720 / +0x88
  jfieldID fidDexCache = (*env)->GetFieldID(env, clazz, "dexCache", "Ljava/lang/Object;");
  (*env)->ExceptionCheck(env);
  jobject dexCacheObj = (*env)->GetObjectField(env, classObj, fidDexCache);// +0x2F8
  jclass  dexCacheCls = (*env)->FindClass(env, "java/lang/DexCache");
  (*env)->GetFieldID(env, dexCacheCls, "dexFile", "I");                    // 试 I(旧)
  if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); }
  jfieldID fidDexFile  = (*env)->GetFieldID(env, dexCacheCls, "dexFile", "J");
  (*env)->ExceptionCheck(env);
  jlong dcDexFile = (*env)->GetLongField(env, dexCacheObj, fidDexFile);    // +0x370

  char rec_name[512] = {0}, rec_len[256] = {0};
  sub_6C760(*(void**)(dcDexFile + 8), *(uint32_t*)(dcDexFile + 16), rec_name, rec_len);

  /* --- 宿主 ClassLoader → pathList → dexElements → base.apk → mCookie --- */
  jclass clsClass    = (*env)->FindClass(env, "java/lang/Class");
  jmethodID midGCL   = (*env)->GetMethodID(env, clsClass, "getClassLoader",
                                           "()Ljava/lang/ClassLoader;");   // +0x108
  jobject classLoader = sub_13DC0(env, classObj, midGCL);                  // CallObjectMethod
  jclass  clClass     = (*env)->GetObjectClass(env, classLoader);          // +0xF8
  jclass  dexFileCls  = (*env)->FindClass(env, "dalvik/system/DexFile");
  jobject pathList    = (*env)->GetObjectField(env, classLoader,
        (*env)->GetFieldID(env, clClass, "pathList", "Ldalvik/system/DexPathList;"));
  jclass  plClass     = (*env)->GetObjectClass(env, pathList);
  jfieldID fidDE      = (*env)->GetFieldID(env, plClass, "dexElements",
                                           "[Ldalvik/system/DexPathList$Element;");
  jobjectArray dexElements = (jobjectArray)(*env)->GetObjectField(env, pathList, fidDE);
  jclass  elemCls     = (*env)->FindClass(env, "dalvik/system/DexPathList$Element");

  jobject elem0 = (*env)->GetObjectArrayElement(env, dexElements, 0);      // +0x568
  jobject pathFile = (*env)->GetObjectField(env, elem0,
        (*env)->GetFieldID(env, elemCls, "path", "Ljava/io/File;"));
  jstring pathStr = (jstring)(*env)->GetObjectField(env, pathFile,
        (*env)->GetFieldID(env, (*env)->FindClass(env, "java/io/File"),
                           "path", "Ljava/lang/String;"));
  const char* apkPath = (*env)->GetStringUTFChars(env, pathStr, 0);        // +0x548
  size_t n1 = strlen(apkPath), n2 = __strlen_chk("base.apk", 9);
  (*env)->DeleteLocalRef(env, pathFile);                    // 【释放】
  (*env)->DeleteLocalRef(env, pathStr);                     // 【释放】
  (void)strncmp(&apkPath[n1 - n2], "base.apk", n2);        // 0x21CCC: 末尾匹配

  jobject hostDexFile = (*env)->GetObjectField(env, elem0,
        (*env)->GetFieldID(env, elemCls, "dexFile", "Ldalvik/system/DexFile;"));
  jobject hostCookie  = (*env)->GetObjectField(env, hostDexFile,
        (*env)->GetFieldID(env, dexFileCls, "mCookie", "Ljava/lang/Object;"));
  jlong* cookie = (*env)->GetLongArrayElements(env, (jlongArray)hostCookie, 0); // +0x5E0
  jlong* csel   = cookie + 1;                     // 0x21D98: 默认跳过 cookie[0]
  /* API == 23 时用 cookie[0]（原代码 csel，patch 后保留） */
  void* dexBegin = *(void**)(*csel + 8);          // 0x21DB4: ArtDexFile->begin_ (+8)
  (*env)->ReleaseLongArrayElements(env, (jlongArray)hostCookie, cookie, 0); // 【释放】+0x620
  (*env)->DeleteLocalRef(env, hostCookie);        // 【释放】
  (*env)->DeleteLocalRef(env, hostDexFile);       // 【释放】
  (*env)->DeleteLocalRef(env, elem0);             // 【释放】

  /* 在 base.apk 内存 DEX 尾部 fdex 记录表里找 dexdata0（file_size 在 header+0x20） */
  sub_6C760(dexBegin, *(uint32_t*)(dexBegin + 32), rec_name, rec_len);      // 0x22100

  /* --- 收尾本段局部引用（原代码连续 DeleteLocalRef ×8） --- */           // 【释放】

  /* ================================================================
   * 阶段 2  解包记录 → Zstd 解压得到载荷
   *   载荷布局: [16B*n 描述符表][0x1000 总头][真实 DEX 数据...]
   * ================================================================ */
  void* rec = rec_name[0] /* 首记录 */;
  sub_6C9A8(rec, *(uint32_t*)rec_len);            // 0x22204 前置: 读大端长度
  uint8_t* payload = sub_6CB50(rec);              // 0x22204: 解包 + Zstd 解压
  qword_129580 = 1;                               // 0x2222C: 就绪标志
  qword_1298A8 = *(uint32_t*)((uint8_t*)*off_1263E8 + 16);   // DEX 数量(配置+16)

  qword_1298B8 = (void**)malloc(8LL * qword_1298A8);  memset(qword_1298B8, 0, 8LL * qword_1298A8);
  qword_1298B0 = (uint32_t*)malloc(4LL * qword_1298A8); memset(qword_1298B0, 0, 4LL * qword_1298A8);

  /* ================================================================
   * 阶段 3  逐 DEX: 解密前 0x20000 + 剥 "BBbb.dgc" + 建方法记录表
   *   (0x22964~0x23460, 主循环 v249 = 0..n-1)
   * ================================================================ */
  void** rec_vec = off_11FC70;                    // 全局: 每个真实 DEX 的记录 vector
  for (uint32_t i = 0; i < qword_1298A8; i++)
  {
    void* rec0 = sub_C9C00(48);                   // 0x2298C: 0x30 DEX 记录
    memset(rec0, 0, 48);

    /* 描述符表在 0x1000 头之前: payload + 0x1000 - 16*n + 16*i, 每项 16B
     *   +0: DEX 相对 0x1000 的偏移(大端u32)  +4: DEX 长度(大端u32) */
    uint8_t* desc = (uint8_t*)payload + 4096 - 16 * qword_1298A8 + 16 * i;
    void* dexPtr = (uint8_t*)payload + 4096
                 + (((uint32_t)desc[0] << 24) | (desc[1] << 16) | (desc[2] << 8) | desc[3]);
    uint32_t dexLen = __builtin_bswap32(*(uint32_t*)(desc + 4));
    qword_1298B8[i] = dexPtr;                     // 0x229D4: 写全局指针表
    qword_1298B0[i] = dexLen;                     // 0x229EC: 写全局长度表
    *(void**)(rec0 + 8) = dexPtr;

    /* --- SM4 解密: 只解前 min(len, 0x20000)，让 ART 能读 header/ID 表 --- */
    uint32_t n = dexLen < 0x20000 ? dexLen : 0x20000;      // 0x22A1C
    void* rk = malloc(0x80);                                // 0x22A28
    sub_293E0(qword_129588, rk);                            // 0x22A38
    uint8_t* plain = malloc(n);                             // 0x22A40
    for (uint32_t off = 0; off < (n >> 4); off++)           // 0x22A5C
      sub_2952C((uint8_t*)dexPtr + off * 16, plain + off * 16, rk);      // 0x22A6C
    memcpy(dexPtr, plain, n & ~0xFULL);                     // 0x22A88: 写回 DEX 映射
    free(rk);                                               // 【释放】0x22A90
    free(plain);                                            // 【释放】0x22A98

    /* --- 扫 "BBbb.dgc" 魔数(0x6367642E62624242), 剥二次封装还原隐藏头 --- */
    int64_t p = (int64_t)dexLen - 9;                        // 0x22A9C
    uint8_t* hit = (uint8_t*)dexPtr + p;
    for (; *(uint64_t*)hit != 0x6367642E62624242ULL; hit--) p--;         // 0x22ACC
    uint32_t tagLen = (hit[-4] << 24) | (hit[-3] << 16) | (hit[-2] << 8) | hit[-1];
    uint8_t* hid = hit - 32 - tagLen;                       // 0x22D06: 隐藏 DEX 头
    *(uint32_t*)(rec0 + 28) = tagLen;
    *(uint64_t*)(rec0 + 16) = (uint64_t)hid;
    *(uint64_t*)(rec0 + 32) = (uint64_t)(hit - 32) - (uint64_t)dexPtr;

    /* --- 隐藏头: +8=方法表偏移(大端) +12=方法数/24 +16=code区偏移(大端) --- */
    void* mvec = sub_C9C00(24); memset(mvec, 0, 24);        // 0x22C80 前的 vector 容器
    *(void**)rec0 = mvec;
    uint32_t mcnt = __builtin_bswap32(*(uint32_t*)(hid + 12)) / 0x18;
    uint64_t codeBase = hid + (((uint64_t)hid[16] << 24) | (hid[17] << 16) | (hid[18] << 8) | hid[19]);
    uint8_t* mtbl = hid + (((uint32_t)hid[8] << 24) | (hid[9] << 16) | (hid[10] << 8) | hid[11]);
    for (uint32_t m = 0; m < mcnt; m++, mtbl += 24)         // 0x22C34 循环
    {
      void* mr = malloc(0x60);                              // 0x22C6C: 方法记录 0x60
      uint32_t relOff = __builtin_bswap32(*(uint32_t*)(mtbl + 0));   // code_item 相对偏移
      uint32_t fieldOff= __builtin_bswap32(*(uint32_t*)(mtbl + 4));  // class_data.code_off 偏移
      uint32_t v12    = __builtin_bswap32(*(uint32_t*)(mtbl + 12));
      uint32_t v16    = __builtin_bswap32(*(uint32_t*)(mtbl + 16));
      *(uint32_t*)(mr + 0x00) = v12;
      *(uint64_t*)(mr + 0x08) = codeBase + relOff;         // code_item 绝对地址
      *(uint32_t*)(mr + 0x18) = fieldOff;
      *(uint32_t*)(mr + 0x20) = v16;                       // code_off 字段的 DEX 偏移
      sub_6CC5C(mvec, mr);                                  // 0x22CB0: push_back
    }
    *(uint32_t*)(rec0 + 40) = *(uint32_t*)(dexPtr + 8);     // 0x231xx: DEX checksum 存档
    sub_6CC5C(rec_vec, rec0);                               // 记录挂到全局 vector
  }
  /* ↑ 循环结束即 0x22D14 汇聚点: 全局表就绪(dump 观测点①) */

  /* ================================================================
   * 阶段 4  空壳 ByteBuffer × n → makeInMemoryDexElements 触发 ART 建真身
   *   (0x23F94~0x24104, API≥29 路径)
   * ================================================================ */
  jobject clsLoader2 = sub_13DC0(env, classObj,
        (*env)->GetMethodID(env, (*env)->FindClass(env, "java/lang/Class"),
                            "getClassLoader", "()Ljava/lang/ClassLoader;"));
  void* elemVec[2] = {0, 0};                      // 新 Element vector(begin,end)
  for (uint32_t i = 0; i < qword_1298A8; i++)
  {
    jobject shellBuf = (*env)->NewDirectByteBuffer(env, qword_120090, 284);  // +0x728: 壳!
    jclass  plCls    = (*env)->FindClass(env, "dalvik/system/DexPathList");
    jmethodID midMDE = (*env)->GetStaticMethodID(env, plCls,
        "makeInMemoryDexElements",
        "([Ljava/nio/ByteBuffer;Ljava/util/List;)[Ldalvik/system/DexPathList$Element;");
    jclass  bbCls     = (*env)->FindClass(env, "java/nio/ByteBuffer");
    jobjectArray bufs = (*env)->NewObjectArray(env, 1, bbCls, 0);            // +0x560
    (*env)->SetObjectArrayElement(env, bufs, 0, shellBuf);                   // +0x570
    jobjectArray elems = (jobjectArray)sub_2C31C(env, plCls, midMDE);        // 0x24084
                                            /* 加载链内部 hook 借此为 n 个真实 DEX
                                               建立 native DexFile 并返回 Element */
    jobject newElem = (*env)->GetObjectArrayElement(env, elems, 0);          // +0x568
    (*env)->DeleteLocalRef(env, plCls);     // 【释放】0x240BC
    (*env)->DeleteLocalRef(env, bbCls);     // 【释放】0x240D4
    (*env)->DeleteLocalRef(env, bufs);      // 【释放】0x240EC
    (*env)->DeleteLocalRef(env, elems);     // 【释放】0x24104
    (*env)->DeleteLocalRef(env, shellBuf);  // 【释放】0x245xx 循环尾
    sub_6CE4C(elemVec, &newElem);           // push 到 Element vector
  }

  /* ================================================================
   * 阶段 5  找 base.apk 的 Java DexFile, 合并 mCookie
   *   (0x2464C~0x24C2C)
   * ================================================================ */
  jclass cl2     = (*env)->GetObjectClass(env, clsLoader2);
  jclass superCl = (*env)->GetSuperclass(env, cl2);                       // +0x50
  jobject hostPL = (*env)->GetObjectField(env, clsLoader2,
        (*env)->GetFieldID(env, superCl, "pathList", "Ldalvik/system/DexPathList;"));
  jclass plCls2  = (*env)->GetObjectClass(env, hostPL);
  jobject hostDE = (*env)->GetObjectField(env, hostPL,
        (*env)->GetFieldID(env, plCls2, "dexElements", "[Ldalvik/system/DexPathList$Element;"));
  jfieldID fidMk = (*env)->GetFieldID(env,
        (*env)->FindClass(env, "dalvik/system/DexFile"), "mCookie", "Ljava/lang/Object;");
  jobject e0   = (*env)->GetObjectArrayElement(env, (jobjectArray)hostDE, 0);
  jobject e0Df = (*env)->GetObjectField(env, e0,
        (*env)->GetFieldID(env, elemCls, "dexFile", "Ldalvik/system/DexFile;"));
  jobject oldCookie = (*env)->GetObjectField(env, e0Df, fidMk);
  jsize  oldLen  = (*env)->GetArrayLength(env, oldCookie);                 // +0x558
  jlong* oldArr  = (*env)->GetLongArrayElements(env, oldCookie, 0);        // +0x5E0
  jsize  addCnt  = (jsize)((void**)elemVec[1] - (void**)elemVec[0]);
  jlongArray merged = (*env)->NewLongArray(env, oldLen + addCnt);          // +0x5A0
  jlong* mergedArr  = (*env)->GetLongArrayElements(env, merged, 0);        // +0x5E0

  for (jsize k = 0; k < oldLen; k++) mergedArr[k] = oldArr[k];             // 0x24B74 拷贝旧
  for (jsize k = 0; k < addCnt; k++)                                       // 0x24BB0
  {
    void* rec  = ((void**)*rec_vec)[k];
    uint64_t st[3] = { (uint64_t)*(void**)(rec + 8),      /* DEX begin(payload 内) */
                       (uint32_t)(uintptr_t)*(uint32_t*)(rec + 24) };/* 长度 */
    sub_10380((uint8_t*)st);                       // 0x24BD0: {begin,len} → jlong cookie 值
    mergedArr[oldLen + k] = (jlong)*(int64_t*)((uint8_t*)st + 16);
  }
  (*env)->ReleaseLongArrayElements(env, merged, mergedArr, 0);             // 【释放】0x24C10
  (*env)->SetObjectField(env, e0Df, fidMk, merged);                        // 0x24C2C: mCookie=merged
  /* 原代码随后 DeleteLocalRef ×12: e0Df/merged/各 class ... */           // 【释放】0x24C38~0x24D90
  free(elemVec[0]);                                                        // 0x24Fxx vector 缓冲

  /* ================================================================
   * 阶段 6  逐 Element: 嫁接 begin_ 到新 native DexFile + ULEB128 回填 code_off
   *   (0x24E80~0x25200)
   * ================================================================ */
  for (uint32_t i = 0; i < (uint32_t)addCnt; i++)                          // 0x24E9C 循环
  {
    jobject elem   = ((jobject*)elemVec[0])[i];
    jobject eDf    = (*env)->GetObjectField(env, elem,
        (*env)->GetFieldID(env, elemCls, "dexFile", "Ldalvik/system/DexFile;"));
    jobject eCk    = (*env)->GetObjectField(env, eDf, fidMk);
    (*env)->GetArrayLength(env, eCk);
    jlong* ck = (*env)->GetLongArrayElements(env, eCk, 0);                 // +0x5E0
    void*  rec = ((void**)*rec_vec)[i];
    void*  realBegin = *(void**)(rec + 8);         // 该 DEX 在 payload 中的真实地址
    *(void**)(ck[1] + 8) = realBegin;              // 0x24FD8: 新 native DexFile->begin_
                                                   /*   嫁接: ART 从 cookie[1]->begin_
                                                       读到的就是解密后的真实 DEX */
    void** mv = *(void***)rec;                     // 方法记录 vector {begin,end}
    for (void** it = mv; it < (void**)mv[1]; it++) // 0x24FE4 循环: 40,415 次量级
    {
      void* mr = *it;
      int64_t codeOff = (int64_t)*(void**)(mr + 8) - (int64_t)realBegin; // 0x25020
      uint8_t* field  = (uint8_t*)realBegin + *(int32_t*)(mr + 0x20);    // class_data.code_off
      /* 5 字节定宽 ULEB128: 续字节... 末字节, 不足补 0x80, 第 5 字节写 0 */
      int w = 0;
      uint32_t t = (uint32_t)codeOff >> 7;
      do { field[w++] = (uint8_t)codeOff | 0x80; codeOff = (int32_t)t; t >>= 7; } while (t);
      field[w++] = (uint8_t)codeOff | 0x80;        // 0x25040 / 0x2507C
      if (w <= 3) { memset(field + w, 0x80, 4 - w); w = 4; }
      field[4] = 0;                                // 0x24FFC: 终止字节
      free(mr);                                    // 【释放】0x25004: 每条方法记录
    }
    (*env)->ReleaseLongArrayElements(env, eCk, ck, 0);   // 【释放】0x251B4
    (*env)->DeleteLocalRef(env, eCk);                    // 【释放】
    (*env)->DeleteLocalRef(env, eDf);                    // 【释放】
  }
  /* ↑ 0x25F68: 回填全部完成、函数未返回 —— dump 观测点② */

  /* ================================================================
   * 阶段 7  收尾与看门狗
   *   (0x25298~0x25F68)
   * ================================================================ */
  /* DeleteLocalRef 清理剩余 class/element 引用 ×N */                     // 【释放】
  free(elemVec[0]);                              // 【释放】vector 缓冲
  /* 解密看门狗目标串(XOR 0xAC), 读 /proc/self/cmdline 比对包名,
   * 打开一个设备/路径, 最后拉起看门狗线程(失败则 1s 间隔重试至多 30 次) */
  // pthread_create(&tid, 0, sub_6EFF0, str);              // 0x25F28
  return;                                        // 0x25F98
}

/* ============================================================================
 * 释放点汇总（执行路径上的全部 free/Release/Delete）:
 *   free:      SM4 轮密钥(0x22A90) / 明文缓冲(0x22A98) / 方法记录 0x60 每条(0x25004)
 *              / Element vector(0x24Fxx, 0x252xx) / 记录 vector
 *   JNI Release: ReleaseLongArrayElements 旧 mCookie(0x21DC4)
 *              / merged cookie(0x24C10) / 各 Element cookie(0x251B4) —— 均 JNI_ABORT=0
 *   JNI Delete:  阶段1 ×8 / 阶段4 每轮 ×5 / 阶段5 ×12 / 阶段6 每轮 ×2 / 阶段7 ×N
 *   注: 全函数无 ReleaseStringUTFChars(apkPath/elem 路径字符串泄漏, 原样保留)
 * ==========================================================================*/
