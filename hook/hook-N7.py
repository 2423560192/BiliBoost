import frida
import sys

rdev = frida.get_remote_device()
session = rdev.attach('哔哩哔哩')

scr = """
Java.perform(function () {


    let d = Java.use("tv.danmaku.biliplayerimpl.report.heartbeat.d");
    d["N7"].implementation = function (hVar, z) {
        console.log(`d.N7 is called: hVar=${hVar}, z=${z}`);
        let result = this["N7"](hVar, z);
        console.log(`d.N7 result=${result}`);
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
