import frida
import sys

rdev = frida.get_remote_device()
pid = rdev.spawn(["tv.danmaku.bili"])
session = rdev.attach(pid)

scr = """
Java.perform(function () {
    let e = Java.use("com.bilibili.api.e");
    e["b"].implementation = function (str) {
    console.log(`e.b is called: str=${str}`);
    console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
    
    this["b"](str);
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