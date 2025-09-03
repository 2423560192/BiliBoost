import frida
import sys

rdev = frida.get_remote_device()
pid = rdev.spawn(["tv.danmaku.bili"])
session = rdev.attach(pid)

scr = """
Java.perform(function () {
    let c = Java.use("com.bilibili.lib.biliid.utils.f.c");
c["a"].implementation = function (context) {
    console.log(`c.a is called: context=${context}`);
    
    console.log(`c.a result=${result}`);
    console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
    let result = this["a"](context);
    return result;
};
});
"""
script = session.create_script(scr)
def on_message(message, data):
    print(message, data)


script.on("message", on_message)
script.load()
rdev.resume(pid)
sys.stdin.read()