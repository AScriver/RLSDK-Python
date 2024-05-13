frida_script = """


function log(message) {
    send({type: "log", message: message});
}

log("Frida script started");

const hooked_functions = new Map();
const hooked_functions_args_map = new Map();
const discovered_functions = new Map();
let scan_active = false;
let process_event_address = null;
let processEvent = null;

let call_stack = [];

// Receive message



recv('process_event_address', function onMessage(payload) {
    log("Received ProcessEvent Address: 0x" + payload.address.toString(16));
    
    process_event_address = payload.address;
    
    processEvent = new NativeFunction(ptr(process_event_address), 'void', ['pointer', 'pointer', 'pointer']);
    
    
    Interceptor.attach(ptr(process_event_address), {


        onEnter: function(args) {
    
   
            // Argument at index 1 is the function address
            const uFunction = args[1];

            // Convert the function address to a string
            const address = uFunction.toString(16)
            
            // If functions are presents in the call stack, call them and pop them

            if (call_stack.length > 0) {
                    call_stack.pop()();
            }

            
            // Check if the function is in the hooked functions map when the scan is active
            if  (scan_active) {

                if (!discovered_functions.has(address)) {
                   
                    discovered_functions.set(address, {
                        count: 1,
                        address: address,
                        thread_id: Process.getCurrentThreadId(),
                    
                    });

                } else {
                   // update count
                    const func = discovered_functions.get(address);
                    func.count += 1;
                    discovered_functions.set(address, func);
                }

            }
            
       
      
            if (hooked_functions.has(address)) {
            
                const casted_args = {}

                // Caller and function are both pointers (8 bytes)

                casted_args.caller = args[0].toString(16)
                casted_args.function = args[1].toString(16)
   

             
                
                hooked_functions_args_map.get(address).forEach((arg, arg_index) => {
                    // args is an array of tuples (type, name, optional size)
                    arg_index += 2; // Skip the first two arguments (caller and function)
             
              
                    const name = arg[0];
                    const type = arg[1];
                    const size = arg[2];


                    // check if args[arg_index] is a null pointer

                    if (args[arg_index].isNull()) {
                        casted_args[name] = null;
                        return;
                    }


                    if (type == "int") {
                        casted_args[name] = args[arg_index].readInt();
                    } else if (type == "uint") {
                        casted_args[name] = args[arg_index].readU32();
                    } else if (type == "uint8") {
                        casted_args[name] = args[arg_index].readU8();
                    } else if (type == "float") {
                        casted_args[name] = args[arg_index].readFloat();
                    } else if (type == "pointer") {
                        casted_args[name] = args[arg_index].toString(16);
                    } else if (type == "bytes") {
                        let buffer = args[arg_index].readByteArray(size);
                        if (buffer) {
                            let bytes = new Uint8Array(buffer);
                            let hexString = '';
                            for (let i = 0; i < bytes.length; i++) {
                                let byte = bytes[i];
                                let hex = byte.toString(16);
                                hexString += (hex.length === 1 ? '0' : '') + hex;
                            }
                            casted_args[name] = hexString;
                        } else {
                            error('Buffer is null');
                        }
                    } else if (type == "fstring") {
                        casted_args[name] = readFString(args[arg_index]);
                      
                    } else if (type == "enum") {
                    
                        casted_args[name] = args[arg_index].readU8();

                    } else {
                        casted_args[name] = args[arg_index];
                    }
              
                    
                });

                send({
                    type: "hooked_function_fired", 
                    address: address, 
                    name: hooked_functions.get(address), 
                    args: casted_args
                });

            }

        }
    });
});


recv('scan_functions', function onMessage(payload) {
    const duration = payload.duration;
    
    log("Start scanning functions for " + duration + " seconds");

    scan_active = true;
    // empty discovered functions
    discovered_functions.clear();

    setTimeout(function() {
        scan_active = false;
        

        // Convertir la map en tableau et trier
        const sortedFunctions = Array.from(discovered_functions.values()).sort((a, b) => b.count - a.count);
        log("Scanning finished: " + sortedFunctions.length + " functions found");
  
        // Envoyer les résultats triés
        send({type: "scan_result", functions: sortedFunctions});



        discovered_functions.clear();

        recv('scan_functions', onMessage);
    }, duration * 1000);
    
})




recv('hook_function', function onMessage(payload) {

    hooked_functions.set(payload.address.toString(16), payload.name);
    hooked_functions_args_map.set(payload.address.toString(16), payload.args_map);

    log("Start hook function: 0x" + payload.address.toString(16) + " " + payload.name);

    recv('hook_function', onMessage);
});

const globalAllocations = [];
function allocateFString(value) {
    const strPtr = Memory.allocUtf16String(value); 

    const strStruct = Memory.alloc(16);
    Memory.writePointer(strStruct, strPtr);  
    Memory.writeInt(strStruct.add(8), value.length + 1);  
    Memory.writeInt(strStruct.add(12), value.length + 1);

    globalAllocations.push(strPtr);

    return strStruct;
}

function readFString(fStringAddr) {
    const dataPtr = Memory.readPointer(fStringAddr);
    const arrayCount = Memory.readInt(fStringAddr.add(8));
    return Memory.readUtf16String(dataPtr, arrayCount * 2 - 2); // Lire la chaîne sans inclure le caractère nul final
}

function dumpMemory(address, length) {
    const buffer = Memory.readByteArray(ptr(address), length);
    console.log(hexdump(buffer, {
        offset: 0,
        length: length,
        header: true,
        ansi: true
    }));
}





recv('call_function', function onMessage(payload) {
    const function_address = ptr(payload.function_address);
    const caller_address = ptr(payload.caller_address);
    const totalSize = payload.total_size;
    let paramsStruct = NULL;
 

    if (payload.args.length > 0) {
      
        paramsStruct = Memory.alloc(totalSize);

        let offset = 0;
        payload.args.forEach(arg => {
            switch (arg.type) {
                case 'float':
                    Memory.writeFloat(paramsStruct.add(offset), parseFloat(arg.value));
                    break;
                case 'int':
                case 'uint':
                case 'uint32':
                case 'bool':
                    Memory.writeInt(paramsStruct.add(offset), parseInt(arg.value));
                    break;
                case 'uint8':
                    Memory.writeU8(paramsStruct.add(offset), parseInt(arg.value));
                    break;
                case 'string':
                    Memory.writeUtf8String(paramsStruct.add(offset), arg.value);             
                    break;
                case 'pointer':
                    Memory.writePointer(paramsStruct.add(offset), ptr(arg.value));
                    break;
                case 'fstring':
                    const fStringStruct = allocateFString(arg.value);
                    Memory.copy(paramsStruct.add(offset), fStringStruct, 16);

                    
                    break;
            }
            
            offset += arg.size
        });
        
        
        
    }

    call_stack.push(function () {

        processEvent(caller_address, function_address, paramsStruct);
    })

    recv('call_function', onMessage);  // Réécouter continuellement
});

"""



