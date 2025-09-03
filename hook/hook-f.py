import frida
import sys

rdev = frida.get_remote_device()
pid = rdev.spawn(["tv.danmaku.bili"])
session = rdev.attach(pid)

scr = """
Java.perform(function () {
    let a = Java.use("com.bilibili.lib.biliid.internal.fingerprint.a.a");
    a["f"].implementation = function (str, aVar) {
        console.log(`a.f is called: str=${str}, aVar=${aVar}`);
        let result = this["f"](str, aVar);
        console.log(`a.f result=${result}`);
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
