import frida
import sys

rdev = frida.get_remote_device()
pid = rdev.spawn(["tv.danmaku.bili"])
session = rdev.attach(pid)

scr = """
Java.perform(function () {
    let a = Java.use("com.bilibili.lib.biliid.internal.fingerprint.a.a");
    a["a"].implementation = function (buvidLegacy, data) {
    console.log(`a.a is called: buvidLegacy=${buvidLegacy}, data=${data}`);
    let result = this["a"](buvidLegacy, data);
    console.log(`a.a result=${result}`);
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
