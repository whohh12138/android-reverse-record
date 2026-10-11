# 广电行销宝

### 目标：app存在root与frida检测，过掉检测，使用frida附加后能进入app登录界面即可。

#### root检测
在root过的手机上打开app，提示设备已root然后app退出。先用magisk模块shamiko隐藏root。

#### frida检测
`frida -U -f com.asiainfo.cbnmarket` frida spwan启动app直接退出。

![1753323934068-fbd1ff0c-c9d2-42f9-82eb-99f77b01abd5.png](./img/vI0seFcR3gqdHsmm/1753323934068-fbd1ff0c-c9d2-42f9-82eb-99f77b01abd5-094755.png)


经过多次附加，发现都是一样的提示，pc 为522。猜测是检测到frida后通过`B 0x522`这样不存在的地址，导致app退出。这里X0、X30、PC都是0x522，所以在010editor中搜索`MOV X0, 0x522`，`MOV X30, 0x522`，的字节码，找到退出点。
![1753350146871-bdd45956-4346-4bba-bcab-329dafa71ab0.png](./img/vI0seFcR3gqdHsmm/1753350146871-bdd45956-4346-4bba-bcab-329dafa71ab0-176878.png)

前面是通过cmp条件b.ne跳转，patch为b直接跳转即可。
![1753361221489-1ab54b36-b8d2-4a53-b1d6-df743d044a8b.png](./img/vI0seFcR3gqdHsmm/1753361221489-1ab54b36-b8d2-4a53-b1d6-df743d044a8b-070464.png)

![1753361236942-f67e932c-cfd8-4628-b5af-204030875f6b.png](./img/vI0seFcR3gqdHsmm/1753361236942-f67e932c-cfd8-4628-b5af-204030875f6b-513159.png)


#### root检测

常用的root检测是通过检测su文件是否存在。hook下file的exists函数找到调用点。然后分析java层函数即可。

![1753765373768-549dbcec-0c18-4e75-8d91-83859f622575.png](./img/vI0seFcR3gqdHsmm/1753765373768-549dbcec-0c18-4e75-8d91-83859f622575-053741.png)

![1753763339082-51026f96-86ea-4248-acec-276dc4133133.png](./img/vI0seFcR3gqdHsmm/1753763339082-51026f96-86ea-4248-acec-276dc4133133-478015.png)

![1753763487256-e533c6e2-cbcb-4004-a47c-0ff39fbe9788.png](./img/vI0seFcR3gqdHsmm/1753763487256-e533c6e2-cbcb-4004-a47c-0ff39fbe9788-097776.png)

![1753763618186-ae13b4ee-6042-4ac5-a5d8-1fe6937d34a8.png](./img/vI0seFcR3gqdHsmm/1753763618186-ae13b4ee-6042-4ac5-a5d8-1fe6937d34a8-504282.png)

j()函数调用了m()函数，通过packagemanager获取packageinfo信息，str为com.topjohnwu.magisk等信息，这里检测magisk等是否安装

![1753763697178-54ddb24b-ad63-4eb3-a856-e62ea488ef1d.png](./img/vI0seFcR3gqdHsmm/1753763697178-54ddb24b-ad63-4eb3-a856-e62ea488ef1d-635535.png)

![1753763674099-02206463-1a24-45dc-b352-9cd8c54f6487.png](./img/vI0seFcR3gqdHsmm/1753763674099-02206463-1a24-45dc-b352-9cd8c54f6487-810034.png)

h()调用了m()函数，检测下面这些应用是否安装

![1753764035114-655ca246-de31-4ab0-897c-2fb8f8274ce7.png](./img/vI0seFcR3gqdHsmm/1753764035114-655ca246-de31-4ab0-897c-2fb8f8274ce7-283947.png)

b()函数判断路径下以及系统环境路径下su是否存在，存在即root

![1753764279062-32ec85ff-8692-4d40-b049-125ac58e8329.png](./img/vI0seFcR3gqdHsmm/1753764279062-32ec85ff-8692-4d40-b049-125ac58e8329-186626.png)

![1753764108351-001dce59-d09e-4696-a594-f55956816a7e.png](./img/vI0seFcR3gqdHsmm/1753764108351-001dce59-d09e-4696-a594-f55956816a7e-275449.png)

c()执行系统命令getprop获取属性，检测ro.debuggable和ro.secure，检测是否修改了系统属性可调试

![1753764423091-f35d5ff9-163a-4eb8-a739-12b45b9963cd.png](./img/vI0seFcR3gqdHsmm/1753764423091-f35d5ff9-163a-4eb8-a739-12b45b9963cd-660944.png)

![1753764430534-cbb8af37-fab0-42b3-b6e5-64e47c975949.png](./img/vI0seFcR3gqdHsmm/1753764430534-cbb8af37-fab0-42b3-b6e5-64e47c975949-672041.png)

e()检测分区是否被挂载为可读写，未root的手机一般为只读

![1753764635877-01e016e0-d310-4181-b36d-5d9f7d0094d6.png](./img/vI0seFcR3gqdHsmm/1753764635877-01e016e0-d310-4181-b36d-5d9f7d0094d6-741862.png)

![1753764647299-386085a7-d0ba-4e8b-9e73-cf1093760a99.png](./img/vI0seFcR3gqdHsmm/1753764647299-386085a7-d0ba-4e8b-9e73-cf1093760a99-694167.png)

![1753764695387-7a67af84-978e-47a7-9fc8-1f4a43c6553f.png](./img/vI0seFcR3gqdHsmm/1753764695387-7a67af84-978e-47a7-9fc8-1f4a43c6553f-110702.png)

l()

![1753764844457-c6393c14-a284-45b7-a1cf-98c3a8927a02.png](./img/vI0seFcR3gqdHsmm/1753764844457-c6393c14-a284-45b7-a1cf-98c3a8927a02-496897.png)

g()还是which su

![1753764872142-b4991f1c-f511-4bb1-8a72-19f52e666ee7.png](./img/vI0seFcR3gqdHsmm/1753764872142-b4991f1c-f511-4bb1-8a72-19f52e666ee7-519700.png)

f()调用native函数检测路径下及系统环境路径su文件是否存在。通过fopen函数打开路径下文件，如果返回文件句柄则是存在文件，即被root

![1753765085626-bad8fbf7-b2d3-4172-a4dc-a836bffa3263.png](./img/vI0seFcR3gqdHsmm/1753765085626-bad8fbf7-b2d3-4172-a4dc-a836bffa3263-473343.png)

![1753765058437-65aba9e2-c82b-4013-a392-d4d567124183.png](./img/vI0seFcR3gqdHsmm/1753765058437-65aba9e2-c82b-4013-a392-d4d567124183-533662.png)

![1753765208024-9abbceb8-b969-4cce-a905-d6314bab8d28.png](./img/vI0seFcR3gqdHsmm/1753765208024-9abbceb8-b969-4cce-a905-d6314bab8d28-680943.png)

d()检测路径下magisk文件是否存在

![1753764926967-94a9388b-6ee1-4592-bd09-e8b528a47319.png](./img/vI0seFcR3gqdHsmm/1753764926967-94a9388b-6ee1-4592-bd09-e8b528a47319-090438.png)

![1753764990954-548b8a4e-6799-484b-a1f2-18959b38e9ba.png](./img/vI0seFcR3gqdHsmm/1753764990954-548b8a4e-6799-484b-a1f2-18959b38e9ba-116060.png)

![1753764967555-e5a4b320-a754-4c54-b435-200488f2290d.png](./img/vI0seFcR3gqdHsmm/1753764967555-e5a4b320-a754-4c54-b435-200488f2290d-861572.png)






#### 最后脚本
<details>
<summary>hook脚本</summary>
<div style="max-height: 400px; overflow-y: auto; padding: 0 10px;">

```javascript
Java.perform(function () {

  var ret = frida_hook("zh.d","a",1);

  function frida_hook (targetClass,targetMethod,exeOringin) {
    // Hook 接口方法
    Java.use(targetClass)[targetMethod].implementation = function () {
      console.log("参数:", JSON.stringify(arguments));
      var stackTrace = Java.use("android.util.Log").getStackTraceString(
        Java.use("java.lang.Throwable").$new()
      );
      console.log("调用栈:\n", stackTrace);
      if(exeOringin){
        var ret = false;
        // var ret = this[targetMethod].apply(this, arguments)
        console.log("ret:",ret,typeof(ret),"\n");
        return ret;
      }else{console.log("no exeOrigin");};

    };
  }

  deDetectFrida();
});

function deDetectRoot() {
  var targetClass = Java.use("vh.a");
  targetClass.a.implementation = function (c, d) {
    // var originalResult = this.a();
    // var modifiedResult = false;
    console.log("[+] Hooked vh.a.a()");
    // console.log("Original return value:", originalResult);
    // console.log("Modified return value:", modifiedResult);
    console.log("\n");
    // return modifiedResult;
  };
}

function deDetectFrida() {
  const system = Java.use('java.lang.System');
  const Runtime = Java.use('java.lang.Runtime');
  const VMStack = Java.use('dalvik.system.VMStack');
  system.loadLibrary.implementation = function (path) {
    console.log(path);
    //this.loadLibrary(path);
    console.log('System.loadLibrary("' + path + '")');

    const loaded = Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), path);

    if (path == "alisecuritysdk") {
      var module = Process.getModuleByName("libalisecuritysdk.so");
      var targetAddress = module.base.add(0x17008);
      var patchedBytes = Memory.readByteArray(targetAddress, 4);
      console.log("Oringin bytes: " + arrayBufferToHex(patchedBytes));
      var newInstructions = [0x07, 0x00, 0x00, 0x14];
      Memory.protect(targetAddress, 4, 'rwx');
      Memory.writeByteArray(targetAddress, newInstructions);
      var patchedBytes = Memory.readByteArray(targetAddress, 4);
      console.log("Patched bytes: " + arrayBufferToHex(patchedBytes));
    }
    console.log("\n");
  }
}

function arrayBufferToHex(buffer) {
  var arr = new Uint8Array(buffer);
  var hex = '';
  for (var i = 0; i < arr.length; i++) {
    var h = arr[i].toString(16);
    hex += (h.length === 1 ? '0' + h : h) + ' ';
  }
  return hex.trim();
}

```
</div>
</details>

#### 结果
![1753765719106-661a8000-562a-441d-b3c6-072b4a21e9f8.png](./img/vI0seFcR3gqdHsmm/1753765719106-661a8000-562a-441d-b3c6-072b4a21e9f8-718124.png)

#### patch相关文件，重打包apk
root检测修改如下，修改为0x0即可

![1753769763694-1a4e90bb-ea4c-48c6-8f1c-e2bc85add7e9.png](./img/vI0seFcR3gqdHsmm/1753769763694-1a4e90bb-ea4c-48c6-8f1c-e2bc85add7e9-385091.png)

frida修改libalisecuritysdk.so即可

![1753769952419-35ba9885-83e5-4075-807d-9b95052c5460.png](./img/vI0seFcR3gqdHsmm/1753769952419-35ba9885-83e5-4075-807d-9b95052c5460-886920.png)
