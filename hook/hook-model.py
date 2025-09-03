import frida
import sys

rdev = frida.get_remote_device()
pid = rdev.spawn(["tv.danmaku.bili"])
session = rdev.attach(pid)

scr = """
Java.perform(function () {
    let g = Java.use("com.bilibili.commons.g");
    g["g"].implementation = function (str) {
    console.log(`g.g is called: str=${str}`);
    let result = this["g"](str);
    console.log(`g.g result=${result}`);
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