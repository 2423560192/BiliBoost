import frida
import sys

rdev = frida.get_remote_device()
session = rdev.attach('哔哩哔哩')

scr = """
Java.perform(function () {
    let a = Java.use("com.bilibili.commons.m.a");
a["g"].implementation = function (bArr, bArr2) {
    console.log(`a.g is called: bArr=${bArr}, bArr2=${bArr2}`);
    let result = this["g"](bArr, bArr2);
    console.log(`a.g result=${result}`);
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
