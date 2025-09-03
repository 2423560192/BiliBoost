function hook_NewStringUTF() {
    var newStringUTF = Module.findExportByName("libart.so", "NewStringUTF");
    if (!newStringUTF) {
        console.log("[!] 没找到 NewStringUTF");
        return;
    }

    Interceptor.attach(newStringUTF, {
        onEnter: function (args) {
            var str = args[1].readCString();
            if (str) {
                console.log("[捕获字符串]:", str, "len:", str.length);
            }
        }
    });
}

// 确认 Java VM 可用
if (Java.available) {
    Java.perform(function () {
        hook_NewStringUTF();
    });
} else {
    console.log("[!] Java VM 不可用，直接尝试 native hook");
    hook_NewStringUTF();
}
