import frida
import sys

rdev = frida.get_remote_device()
session = rdev.attach('哔哩哔哩')

scr = """
Java.perform(function () {
    let a = Java.use("com.bilibili.lib.biliid.utils.f.a");
a["c"].implementation = function (context) {
    console.log(`a.c is called: context=${context}`);
    let result = this["c"](context);
    console.log(`a.c result=${result}`);
    return result;
};
});
"""
script = session.create_script(scr)


def on_message(message, data):
    print(message, data)


script.on("message", on_message)
script.load()
sys.stdin.read()
