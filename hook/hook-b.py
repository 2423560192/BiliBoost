import frida
import sys

rdev = frida.get_remote_device()
session = rdev.attach('哔哩哔哩')

scr = """
Java.perform(function () {
    let b = Java.use("t3.a.i.a.a.a.b");
    b["b"].implementation = function (params) {
        console.log(`b.b is called: params=${params}`);
        let result = this["b"](params);
        console.log(`b.b result=${result}`);
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
