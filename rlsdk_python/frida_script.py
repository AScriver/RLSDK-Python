frida_script = """
console.log("Frida script started");

const hooked_functions = new Map();
const hooked_functions_args_map = new Map();
const discovered_functions = new Map();
let scan_active = false;


// Receive message

recv('process_event_address', function onMessage(payload) {
    console.log("Received ProcessEvent Address: 0x" + payload.address.toString(16));


    Interceptor.attach(ptr(payload.address), {
        onEnter: function(args) {
            // Le deuxième argument est le pointeur vers UFunction
            const uFunction = args[1];

            const address = uFunction.toString(16)

            if  (scan_active) {
                discovered_functions.set(address, address);
            }

      
            if (hooked_functions.has(address)) {
            
                const casted_args = {}

                // Caller and function are both pointers (8 bytes)

                casted_args.caller = args[0].toString(16)
                casted_args.function = args[1].toString(16)
   

            
                

                hooked_functions_args_map.get(address).forEach((arg) => {
                    // args is an array of tuples (index, type, name)

                    const index = arg[0];
                    const type = arg[1];
                    const name = arg[2];
                    const size = arg[3];

                    if (type == "int") {
                        casted_args[name] = args[index].readInt();
                    } else if (type == "uint") {
                        casted_args[name] = args[index].readU32();
                    } else if (type == "float") {
                        casted_args[name] = args[index].readFloat();
                    } else if (type == "address") {
                        casted_args[name] = args[index].toString(16);
                    } else if (type == "bytes") {
                        let buffer = args[index].readByteArray(size);
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
                            console.error('Buffer is null');
                        }
                    } else {
                        casted_args[name] = args[index];
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
    
    console.log("Start scanning functions for " + duration + " seconds");

    scan_active = true;
    // empty discovered functions
    discovered_functions.clear();

    setTimeout(function() {
        scan_active = false;
        send({type: "scan_result", functions: Array.from(discovered_functions.keys())});
        discovered_functions.clear();
        recv('scan_functions', onMessage);
    }, duration * 1000);
    
})




recv('hook_function', function onMessage(payload) {

    hooked_functions.set(payload.address.toString(16), payload.name);
    hooked_functions_args_map.set(payload.address.toString(16), payload.args_map);

    console.log("Received Hook Function: 0x" + payload.address.toString(16) + " " + payload.name);

    recv('hook_function', onMessage);
});
"""

