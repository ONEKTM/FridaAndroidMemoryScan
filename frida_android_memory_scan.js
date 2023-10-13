/* 
Usage:
    1.Modify the value of the pattern variable as the search target
    2.frida -U -f [packageName] -l frida_android_memory_scan.js --no-pause
*/

function memscan() {
    Java.perform(function () {

        var pattern = "7f 45 4c 46";
        // var pattern = "4d 41 47 49 53 4b"; //echo "MAGISK" |hexdump -C 

        var mapsPath = "/proc/" + Process.id + "/maps";

        const fopenPtr = Module.getExportByName(null, "fopen");
        var fopenFun = new NativeFunction(fopenPtr, 'pointer', ['pointer', 'pointer']);
        const sprintfPtr = Module.getExportByName(null, "sprintf");
        var sprintfFun = new NativeFunction(sprintfPtr, 'int', ['pointer', 'pointer']);
        const fgetsPtr = Module.getExportByName(null, "fgets");
        var fgetsFun = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
        const sscanfPtr = Module.getExportByName(null, "sscanf");
        var sscanfFun = new NativeFunction(sscanfPtr, 'int', ['pointer', 'pointer', 'pointer','pointer','pointer', 'pointer','pointer']);
        const fclosePtr = Module.getExportByName(null, "fclose");
        var fcloseFun = new NativeFunction(fclosePtr, 'int', ['pointer']);

        var filePtr = fopenFun(Memory.allocUtf8String(mapsPath), Memory.allocUtf8String("r"));
        const buffer = Memory.alloc(1024);
        const content = Memory.alloc(1024);
        var num = 0;

        while(!fgetsFun(buffer, 1024, filePtr).isNull()) {
            const start = Memory.alloc(8);
            const end = Memory.alloc(8);
            const r = Memory.allocUtf8String(' ');
            const x = Memory.allocUtf8String(' ');

            sscanfFun(buffer, Memory.allocUtf8String("%lx-%lx %c%*c%c%*c %*s %*s %*d%1023[^\n]"), start, end, r, x, content);

            if (r.readUtf8String() == "r") {

                var start_value = start.readULong();
                var end_value = end.readULong();
                var entry = content.readUtf8String().trim();
                var size = end_value - start_value;
                const pagecheck = 4096;

                //     console.log('行内容:', start, end, r.readUtf8String(), content.readUtf8String());

                var File = Java.use("java.io.File");
                var file = File.$new(entry);
                var fileExists = file.exists();
                if (fileExists) {//当文件实际大小小于内存段时, 超过文件大小的部分没有权限读
                    var fileSize = file.length();
                    size = fileSize < size ? fileSize : size;
                }

                var times = Math.floor(size / pagecheck);
                if (times < 5) { //小于5页的不扫了
                    continue;
                }
                for(let i = 0; i < times; i++) {
                    // var range = Process.findRangeByAddress(start.readPointer());
                    // if (range === null){
                    //     continue;
                    // }
                    // Memory.protect(start.readPointer().add(i*pagecheck), pagecheck, range.protection);
                    var scanSync = Memory.scanSync(start.readPointer().add(i*pagecheck), pagecheck, pattern);
                    if (scanSync.length > 0) {
                        console.log("#内存扫描到结果:" + JSON.stringify(scanSync) + "\n*地址所在段信息:\n", buffer.readUtf8String());
                    }
                }

                num++;
            }
        }

        console.log("扫描结束。。。。。。。。。。。。。。。。。 共扫描可读项:" + num);
        fcloseFun(filePtr);

    });
}
setImmediate(memscan,0);
