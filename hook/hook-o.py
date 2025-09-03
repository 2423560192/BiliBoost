import frida
import sys

rdev = frida.get_remote_device()
pid = rdev.spawn(["tv.danmaku.bili"])
session = rdev.attach(pid)

scr = """
Java.perform(function () {
    let a = Java.use("com.bilibili.api.a");
    a["o"].implementation = function (bVar) {
        console.log(`a.o is called: bVar=${bVar}`);
        console.log(JSON.stringify(bVar));
        this["o"](bVar);
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
