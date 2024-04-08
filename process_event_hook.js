console.log("Frida script started");

const hooked_functions = new Map();
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

           
   
            if(hooked_functions.has(address)) {
                send({type: "hooked_function_fired", address: address, name: hooked_functions.get(address), args: args});
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

    console.log("Received Hook Function: 0x" + payload.address.toString(16) + " " + payload.name);

    recv('hook_function', onMessage);
});


// setTimeout(function() {
//     // displayu all discovered functions addresses
//     console.log("Discovered functions: ");
//     for (let [key, value] of discovered_functions) {
//         console.log(key);
//     }   
// }, 10000);



// // [000001] 000000000363FC00 Class Core.Object

// const Core_Object = ptr("0x355fc00")



// // Read pointer to the vtable

// const vtable = Core_Object.readPointer()

// // Read the function at the index 67 to find the processEvent function

// const processEvent = vtable.add(67 * Process.pointerSize).readPointer()



// console.log("processEvent: " + processEvent)

// Interceptor.attach(ptr(0x7ff7ceef40b0), {
//     onEnter: function(args) {
//         // Le deuxième argument est le pointeur vers UFunction
//         const uFunction = args[1];
//         console.log("UFunction: " + uFunction)

//         if(0x2486A800 == uFunction) {
//             // Display in green
//             const deltaTime = Memory.readFloat(args[2])
//             console.log("PlayerTick: deltaTime = " + deltaTime)

//             // convert args[2] to float

           
//         }
        
//         // // Hypothétique offset où se trouve le nom; cela dépend de la version d'UE
//         // const nameOffset = 0x0048; // Cet offset est un exemple, ajuste-le pour ta version
        
//         // // Lire le pointeur vers le nom de la fonction
//         // const namePtr = uFunction.add(nameOffset).readPointer();
        
//         // // Lire le nom de la fonction. Ceci est simplifié; la réalité peut nécessiter de manipuler FName ou d'autres structures
//         // const functionName = namePtr.readCString();

//         // console.log("Nom de la fonction : " + functionName);
//     }
// });