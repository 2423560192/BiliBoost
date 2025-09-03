import frida
import sys

rdev = frida.get_remote_device()
pid = rdev.spawn(["tv.danmaku.bili"])
session = rdev.attach(pid)

scr = """
Java.perform(function () {
    var c = Java.use("com.bilibili.api.c");

    c.b.implementation = function(arg0){   
       console.log("buvid=",arg0);
       // 打印这句话，就会打印出 b 方法的调用栈关系
       console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
       this.b(arg0);
    }
});
"""
script = session.create_script(scr)
def on_message(message, data):
    print(message, data)


script.on("message", on_message)
script.load()
rdev.resume(pid)
sys.stdin.read()