import frida
import sys

rdev = frida.get_remote_device()
session = rdev.attach('哔哩哔哩')

scr = """
Java.perform(function () {
    let b = Java.use("t3.a.i.a.a.a.b");
    b["a"].implementation = function (body) {
        console.log(`b.a is called: body=${body}`);
        let result = this["a"](body);
        console.log(`b.a result=${result}`);
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
