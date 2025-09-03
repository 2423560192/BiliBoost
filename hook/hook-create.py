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

    
    let d = Java.use("tv.danmaku.biliplayerimpl.report.heartbeat.d");
    d["H7"].implementation = function (j2, j4, i, j5, j6, i2, i3, j7, str, i4, str2, str3) {
        console.log(`d.H7 is called: j2=${j2}, j4=${j4}, i=${i}, j5=${j5}, j6=${j6}, i2=${i2}, i3=${i3}, j7=${j7}, str=${str}, i4=${i4}, str2=${str2}, str3=${str3}`);
        let result = this["H7"](j2, j4, i, j5, j6, i2, i3, j7, str, i4, str2, str3);
        console.log(`d.H7 result=${result}`);
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
