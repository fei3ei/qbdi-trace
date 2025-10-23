function prepareArgs(args) {
    if (args === undefined || !Array.isArray(args)) {
        args = [];
    }
    var argNum = args.length;
    var argSize = Process.pointerSize * argNum;
    var argsPtr = Memory.alloc(argSize);

    for (var i = 0; i < argNum; i++) {
        var arg = args[i];
        var argPtr;
        if (!arg) {
            arg = 0
        }
        if (arg instanceof NativePointer) {
            // 如果是 NativePointer，直接使用
            argPtr = arg;
        } else if (typeof arg === 'number') {
            // 如果是数字，直接转换为指针
            argPtr = ptr(arg);
        } else if (typeof arg === 'string') {
            // 如果是字符串，分配内存并获取指针
            argPtr = Memory.allocUtf8String(arg);
        } else if (typeof arg === 'object' && arg.hasOwnProperty('handle')) {
            // 如果是带有 handle 属性的对象（如 JNIEnv）
            argPtr = arg.handle;
        } else if (typeof arg === 'object' && arg instanceof ArrayBuffer) {
            // 如果是二进制数据，分配内存并写入数据
            var dataPtr = Memory.alloc(arg.byteLength);
            Memory.writeByteArray(dataPtr, arg);
            argPtr = dataPtr;
        } else {
            console.error('Unsupported argument type at index ' + i + ':', typeof arg);
            throw new TypeError('Unsupported argument type at index ' + i + ': ' + typeof arg);
        }
        // 将参数指针写入参数数组
        Memory.writePointer(argsPtr.add(i * Process.pointerSize), argPtr);
    }

    return {
        argsPtr: argsPtr,
        argNum: argNum
    };
}

var traceSoname = //TODO;
var subFunctionoffset = //TODO;
var packageName = //TODO;
function hook_sub_function() {
    var mainBase = Module.findBaseAddress(traceSoname);
    console.log(`[+] start trace ${traceSoname} 0x${subFunctionoffset.toString(16)}`);
    var targetFuncAddr = mainBase.add(subFunctionoffset);
    Interceptor.replace(targetFuncAddr, new NativeCallback(function (arg0,arg1,arg2,arg3,arg4,arg5) {
        Interceptor.revert(targetFuncAddr);
        Interceptor.flush();
        var args =[arg0,arg1,arg2,arg3,arg4,arg5];
        var {argsPtr, argNum} = prepareArgs(args);
        var logPath = "/data/data/" + packageName + `/sub_0x${subFunctionoffset.toString(16)}_log.txt`;
        var logPtr = Memory.allocUtf8String(logPath);
        console.log("[+] Traced function called!!!!!!");
        var res = vmtrace(targetFuncAddr, argsPtr, 6, logPtr);
        console.log("[+] Traced function end!!!!!!");
        return res;
    }, 'pointer', ['pointer','pointer','pointer','pointer','pointer','pointer']));
}

var vmtrace;
function vmtrace_init() {
    var  dlopenPtr = Module.findExportByName(null, 'dlopen');
    var  dlopen = new NativeFunction(dlopenPtr, 'pointer', ['pointer', 'int']);
    var soPath = "/data/local/tmp/libqbditrace.so"; // 示例路径
    var  soPathPtr = Memory.allocUtf8String(soPath);
    var handle = dlopen(soPathPtr, 2);
    var vmtraceAddr = Module.findExportByName("libqbditrace.so", 'start_trace');
    vmtrace = new NativeFunction(vmtraceAddr, 'pointer', ['pointer', 'pointer', 'uint32', 'pointer']);

}

function hook_call_constructors() {
    let get_soname = null;
    let call_constructors_addr = null;
    let hook_call_constructors_addr = true;

    let linker = null;
    if (Process.pointerSize == 4) {
        linker = Process.findModuleByName("linker");
    } else {
        linker = Process.findModuleByName("linker64");
    }

    let symbols = linker.enumerateSymbols();
    for (let index = 0; index < symbols.length; index++) {
        let symbol = symbols[index];
        if (symbol.name == "__dl__ZN6soinfo17call_constructorsEv") {
            call_constructors_addr = symbol.address;
        } else if (symbol.name == "__dl__ZNK6soinfo10get_sonameEv") {
            get_soname = new NativeFunction(symbol.address, "pointer", ["pointer"]);
        }
    }
    if (hook_call_constructors_addr && call_constructors_addr && get_soname) {
        let h = Interceptor.attach(call_constructors_addr,{
            onEnter: function(args){
                let soinfo = args[0];
                let soname = get_soname(soinfo).readCString();
                if (soname && soname.indexOf(traceSoname) != -1) {
                    hook_sub_function();
                    h.detach();
                }
            }
        });
    }
}

function main(){
    vmtrace_init();
    hook_call_constructors();

}

setImmediate(main)