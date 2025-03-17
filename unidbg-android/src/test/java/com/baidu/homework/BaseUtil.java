package com.baidu.homework;

import com.alibaba.fastjson.JSONObject;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.EmulatorBuilder;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.hook.hookzz.*;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.file.SimpleFileIO;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.unix.struct.TimeVal32;
import com.github.unidbg.utils.Inspector;
import okhttp3.*;

import java.io.File;
import java.io.IOException;
import java.util.Map;

/**
 * @author Tiam
 * @date 2025/1/8 10:39
 * @description Bean
 */
public class BaseUtil extends AbstractJni implements IOResolver<AndroidFileIO> {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;
    private final DvmClass cNativeHelper;

    public static String pkgName = "com.baidu.homework";
    // public static String apkPath = "zyb/作业帮14.17.0.apk";
    public static String soPath = "unidbg-android/src/test/resources/zyb/libbaseutil.so";
    public static String apkPath = "unidbg-android/src/test/resources/zyb/作业帮_14.18.0_APKPure.apk";

    public BaseUtil() {
        // 1. 创建 64位模拟器设备, so应该对应64位的
        EmulatorBuilder<AndroidEmulator> builder = AndroidEmulatorBuilder.for64Bit()
                // 指定进程名，推荐以安卓包名做进程名
                .setProcessName(pkgName);
        // 动态引擎
        if (false) {
            builder.addBackendFactory(new DynarmicFactory(true));
        }
        emulator = builder.build();
        // 2. 获取 emulator 内存管理器
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        // 3. 指定apk文件, 创建虚拟机 new File(apkPath)
        // vm = emulator.createDalvikVM(new File(apkPath));
        vm = emulator.createDalvikVM();
        // vm.setDvmClassFactory(new ProxyClassFactory());
        vm.setJni(this); // 绑定 JNI 接口, 后续设置补环境 !!!!
        vm.setVerbose(true); // 是否打印日志

        // emulator.getSyscallHandler().addIOResolver(this);
        cNativeHelper = vm.resolveClass("com/zuoyebang/baseutil/NativeHelper");
        // 4. 加载执行 so 文件
        DalvikModule dm = vm.loadLibrary(new File(soPath), false);
        dm.callJNI_OnLoad(emulator);
        // 5. 获取本SO模块的句柄,后续需要用它
        module = dm.getModule();
        System.out.println("so在Unidbg虚拟内存中的基地址: " + module.base);
        // init(cuid);
    }

    @Override
    public DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        switch (signature) {
            case "android/content/Context->getPackageName()Ljava/lang/String;":
                return new StringObject(vm, "com.baidu.homework");
            case "android/content/pm/Signature->toCharsString()Ljava/lang/String;":
                // TODO apk版本升级时, 值可能变化
                return new StringObject(vm, "308201923081fca00302010202044d3c2820300d06092a864886f70d0101050500300d310b300906035504031302796b3020170d3131303132333133303734345a180f32303831303130353133303734345a300d310b300906035504031302796b30819f300d06092a864886f70d010101050003818d003081890281810095a1a931cc6bbc8899441e614f469104e2520a95ff90942ba177d336d98b1a5d6a637a0e95d1a3cc630537ecb1a5c708b5751d8f13bf8ba993b95748ed15b87c6dc22bf76e97f7ad68d86cad686752a48ce0cba009065a5f17650ab2301b9b871e3d0682712c0914a6b97df5b15ad15c14f080410b562973f830f31a31a75f970203010001300d06092a864886f70d0101050500038181002e5332040bde9448f53c63472c3a210da2101afe353538253072d643f089eb7eab68f0db2cedfb115bb73d2116db5fc0f516259f41ac0c04ee3b5e00710469d654b2d17a8330ad601e58f8d630afbc75420b9c55f62de033bcf02bdd9a1014d376576d048bebbe84a88826d9230527b5078bf08724cafb847ae64fa0e9aca40f");
        }
        return super.callObjectMethod(vm, dvmObject, signature, varArg);
    }

    @Override
    public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        switch (signature) {
            case "android/content/pm/PackageInfo->signatures:[Landroid/content/pm/Signature;":
                // 只通过hashcode和toCharString()对比校验, 此处无所谓
                byte[] sign = new byte[256];
                DvmObject<?> signature1 = vm.resolveClass("android/content/pm/Signature").newObject(sign);
                DvmObject<?>[] signatures = {signature1};
                return new ArrayObject(signatures);
        }
        return super.getObjectField(vm, dvmObject, signature);
    }

    @Override
    public int callIntMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        switch (signature) {
            case "android/content/pm/Signature->hashCode()I":
                // TODO apk版本升级时, 值可能变化
                return 0xd5fbc2fa;
        }
        return super.callIntMethod(vm, dvmObject, signature, varArg);
    }

    @Override
    public FileResult resolve(Emulator emulator, String pathname, int oflags) {
        switch (pathname){
            case "/proc/self/maps":{
                return FileResult.<AndroidFileIO>success(new SimpleFileIO(oflags, new File("unidbg-android/src/test/resources/zyb/maps"), pathname));
            }
        }
        return null;
    }

    public void destroy() throws IOException {
        emulator.close();
    }

    public String initAppAntiSpam(String signA, String cuid) {
        OkHttpClient client = new OkHttpClient();
        RequestBody formBody = new FormBody.Builder()
                .add("data", signA)
                .add("screensize", "2400x1080")
                .add("physicssize", "6.673375786872029")
                .add("city", "")
                .add("channel", "xiaomi")
                .add("appBit", "64")
                .add("dayivc", "65")
                // .add("adid", "a4d64e8af411bef7b325a45827da531bc438073e")
                .add("adid", "c465f365a7dc30a4d96669d2468cd9c4fc5373d7")
                .add("province", "")
                .add("zbkvc", "960")
                .add("pkgName", "com.baidu.homework")
                .add("appId", "homework")
                .add("feSkinName", "skin-gray")
                .add("screenscale", "2.75")
                .add("area", "")
                .add("deviceType", "Phone")
                // .add("cuid", "7AF43243C094AA9A44325CDA78FC5CB5|0")
                .add("cuid", cuid)
                .add("os", "android")
                .add("abis", "1")
                .add("personalRecommendNA", "1")
                .add("vc", "1860")
                .add("token", "1_XPXQH3c5HRPtFHkSwi3sCCURmT25QfxM")
                .add("hybrid", "1")
                .add("androidVersion", "14")
                .add("vcname", "14.18.0")
                .add("sdk", "34")
                // todo 这些设备参数是否需要修改随机？
                .add("operatorid", "46001")
                .add("device", "22021211RC")
                .build();

        Request request = new Request.Builder()
                .url("https://pluto.zuoyebang.com/pluto/app/antispam")
                .post(formBody)
                .header("User-Agent",
                        "Mozilla/5.0 (Linux; Android 14; 22021211RC Build/UKQ1.231207.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/120.0.6099.193 Mobile Safari/537.36")
                .header("x-wap-proxy-cookie", "none")
                .header("x-zyb-trace-t", "1736328191305")
                .header("content-type", "application/x-www-form-urlencoded; charset=UTF-8")
                // .header("zyb-cuid", "7AF43243C094AA9A44325CDA78FC5CB5|0")
                // .header("zyb-adid", "a4d64e8af411bef7b325a45827da531bc438073e")
                .header("zyb-cuid", cuid)
                .header("zyb-adid", "c465f365a7dc30a4d96669d2468cd9c4fc5373d7")
                .header("na__zyb_source__", "homework")
                .header("x-zyb-trace-id", "1b8ebbdeed3189f3:1b8ebbdeed3189f3:0:1")
                .build();

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful())
                throw new IOException("Unexpected code " + response);
            String resp = response.body().string();
            // {"errNo":7,"errstr":"反作弊模块-握手数据错误","data":{}}
            // {"errNo":7,"errstr":"antispam data error","data":[]}
            System.out.println("请求signB: " + resp);
            Map map = JSONObject.parseObject(resp, Map.class);
            if ((int) map.get("errNo") != 0) {
                throw new RuntimeException("initAppAntiSpam error: " + map.get("errstr"));
            }
            Map data = JSONObject.parseObject(map.get("data").toString(), Map.class);
            return (String) data.get("data");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public String nativeInitBaseUtil(Object context, String cuid) {
        DvmObject<?> result = cNativeHelper.callStaticJniMethodObject(emulator,
                "nativeInitBaseUtil(Landroid/content/Context;Ljava/lang/String;)Ljava/lang/String;",
                context, cuid);
        // 这里的返回值为 nativeSetToken方法参数 signA (每次不同, 由于 getChallenge 随机性导致)
        return result.getValue().toString();
    }

    public String nativeInitBaseUtil(String cuid) {
        DvmObject<?> context = vm.resolveClass("android/content/Context").newObject(null);
        return nativeInitBaseUtil(context, cuid);
    }

    public boolean nativeSetToken(Object context, String cuid, String signA, String signB) {
        return cNativeHelper.callStaticJniMethodBoolean(emulator,
                "nativeSetToken(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z",
                context, cuid, signA, signB);
    }

    public boolean nativeSetToken(String cuid, String signA, String signB) {
        DvmObject<?> context = vm.resolveClass("android/content/Context").newObject(null);
        return nativeSetToken(context, cuid, signA, signB);
    }

    public String nativeGetRandom() {
        return cNativeHelper.callStaticJniMethodObject(emulator,
                "nativeGetRandom()Ljava/lang/String;").getValue().toString();
    }

    public String nativeGetKey(String vc) {
        DvmObject<?> result = cNativeHelper.callStaticJniMethodObject(emulator,
                "nativeGetKey(Ljava/lang/String;)Ljava/lang/String;", vc);
        return result.getValue().toString();
    }

    public String nativeGetSign(String payload) {
        DvmObject<?> sign = cNativeHelper.callStaticJniMethodObject(emulator,
                "nativeGetSign(Ljava/lang/String;)Ljava/lang/String;",
                payload);
        return sign.getValue().toString();
    }

    public void init(String cuid) {
        System.out.println("客户唯一标识符：" + cuid);
        DvmObject<?> context = vm.resolveClass("android/content/Context").newObject(null);
        // String cuid = "7AF43243C094AA9A44325CDA78FC5CB5|0";
        // String cuid = "5C7CBF43D68B0E8697167DC58369AAA5|0";
        // String cuid = "811BF336637EE3CE3676ADDDA0B74F1E|0";
        String signA = nativeInitBaseUtil(context, cuid);
        // String signA =
        // "0b030d00080e0a000a0a04040a050e0a0f090a0f060a050c0c020e010d07030b0a0d0a030a0b0c050d0e0607080602020a090d0c0507030f090a050a0407050d060d0c09030a080d04020105010508060b080e0f090804010405080c0a0d0601090209010d020a040404070e090f02020a0300020a0e060e09020d0f0e0902090a020e020c0a0803030d0f020703060c0d000408080c0d080d0f090b0c060a0c000d0f0d030b0a0a050f0c0f030f0b0e";
        String signB = initAppAntiSpam(signA, cuid);
        System.out.println("96位signB, initAppAntiSpam: " + signB);
        // String signB =
        // "0e0f0c0805090f01010d0606090503050102010402060308040d0c080c080d05070b0509050f0c090b0e0c0305040905";
        boolean bol = nativeSetToken(context, cuid, signA, signB);
        System.out.println("环境成功时这里应该返回true, nativeSetToken: " + bol);
        String random = nativeGetRandom();
        System.out.println("nativeGetRandom: " + random);
    }

    public void callJniFunction() {
        String cuid = "7AF43243C094AA9A44325CDA78FC5CB5|0";
        // 0x1060 nativeInitBaseUtil
        // 0x1160 init
        Number number = module.callFunction(emulator, 0x1060,
                vm.getJNIEnv(),
                0,
                vm.addLocalObject(vm.resolveClass("android/content/Context").newObject(null)),
                vm.addLocalObject(new StringObject(vm, cuid))
        );
        System.out.println("result: " + vm.getObject(number.intValue()).getValue());
    }
    /**
     * 固定随机函数
     */
    public void hook_rand() {
        IHookZz hookZz = HookZz.getInstance(emulator);
        hookZz.enable_arm_arm64_b_branch();
        hookZz.wrap(module.findSymbolByName("rand"), new WrapCallback<HookZzArm64RegisterContext>() {
            @Override
            public void preCall(Emulator<?> emulator, HookZzArm64RegisterContext ctx, HookEntryInfo info) {
            }

            @Override
            public void postCall(Emulator<?> emulator, HookZzArm64RegisterContext ctx, HookEntryInfo info) {
                ctx.setXLong(0, 1L);
            }
        });
    }

    /**
     * 固定时间
     */
    public void hook_time() {
        HookZz instance = HookZz.getInstance(emulator);
        instance.wrap(module.findSymbolByName("gettimeofday"), new WrapCallback<HookZzArm32RegisterContext>() {
            UnidbgPointer tv = null;  // 初始化Pointer指针

            @Override  // hook前
            public void preCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
                tv = ctx.getPointerArg(0);  // 将指针赋值给tv
            }

            @Override // hook后
            public void postCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
                if (tv != null) {
                    byte[] before = tv.getByteArray(0, 12);
                    Inspector.inspect(before, "gettimeofday tv");
                }
                System.out.println("====++++====");
                // 固定时间
                long currentTimeMillis = 1668083944037L;
                long tv_sec = currentTimeMillis / 1000;
                long tv_usec = (currentTimeMillis % 1000) * 1000;
                System.out.println("=======");
                System.out.println(currentTimeMillis);
                System.out.println(tv_sec);
                System.out.println(tv_usec);
                // 创建TimeVal32时间对象，并传入指针
                TimeVal32 TimeVal = new TimeVal32(tv);
                TimeVal.tv_sec = (int) tv_sec;
                TimeVal.tv_usec = (int) tv_usec;
                TimeVal.pack();  // 替换
            }
        });
    }

    public void addBreakPoint() {
        emulator.attach().addBreakPoint(module.base + 0x638c);
    }

    public void test1() {
        String cuid = "7AF43243C094AA9A44325CDA78FC5CB5|0";
        DvmObject<?> context = vm.resolveClass("android/content/Context").newObject(null);
        String signA = nativeInitBaseUtil(context, cuid);
        System.out.println("352位signA:" + signA);
        String signB = initAppAntiSpam(signA, cuid);
        System.out.println("96位signB, initAppAntiSpam: " + signB);
        boolean bol = nativeSetToken(context, cuid, signA, signB);
        System.out.println("环境成功时这里应该返回true, nativeSetToken: " + bol);
        String rc4_key = nativeGetKey("1860");
        System.out.println("rc4_key: " + rc4_key);
        String random = nativeGetRandom();
        System.out.println("nativeGetRandom: " + random);
    }

    public void test() {
        int address = (int) module.findSymbolByName("CRYMd5").getAddress();
        System.out.println(address);
//        Number number = module.callFunction(emulator, 0x6b4c,
//                vm.getJNIEnv(),
//                0
//        );
//        System.out.println("result: " + vm.getObject(number.intValue()).getValue());
    }

    public static void main(String[] args) {
        BaseUtil baseUtilService = new BaseUtil();
        // baseUtilService.test();
        baseUtilService.hook_rand();
        baseUtilService.addBreakPoint();
        baseUtilService.callJniFunction();
    }
}
