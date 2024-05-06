import pymem
import pymem.pattern
import ctypes
import frida
import time
import threading
from typing import Callable, Any, Protocol
from .event_handling import Event
from .events import EventFunctionHooked, EventBoostPadChanged, EventTypes, EventPlayerTick, EventRoundActiveStateChanged, EventResetPickups, EventGameEventStarted, EventKeyPressed, EventGameEventDestroyed
from .game_objects import UClass, UFunction, GameEvent, TArray, UObject, FNameEntry, FName, Field, VehiclePickupBoost, GameViewportClient
from .frida_script import frida_script
from colorama import Fore, Back, Style, just_fix_windows_console
from tqdm import tqdm
import json

PROCESS_NAME = "RocketLeague.exe"

FUNCTION_PICKED_UP = "Function TAGame.VehiclePickup_TA.OnPickUp"
FUNCTION_PLAYER_TICK = "Function Engine.PlayerController.PlayerTick"
FUNCTION_KEY_PRESS = "Function TAGame.GameViewportClient_TA.HandleKeyPress"
FUNCTION_BALL_CAR_TOUCH= "Function TAGame.Ball_TA.EventCarTouch"
FUNCTION_SET_VEHICLE_INPUT = "Function TAGame.Car_TA.SetVehicleInput"
FUNCTION_PICKUP_TOUCH = "Function TAGame.VehiclePickup_TA.Touch"
FUNCTION_BALL_ON_RIGID_BODY_COLLISION = "Function TAGame.Ball_TA.OnRigidBodyCollision"
FUNCTION_BOOST_PICKED_UP = "Function TAGame.VehiclePickup_Boost_TA.Idle.EndState"
FUNCTION_BOOST_RESPAWN = "Function TAGame.VehiclePickup_Boost_TA.Idle.BeginState"
FUNCTION_ROUND_ACTIVE_BEGIN = "Function TAGame.GameEvent_Soccar_TA.Active.BeginState"
FUNCTION_ROUND_ACTIVE_END = "Function TAGame.GameEvent_Soccar_TA.Active.EndState"
FUNCTION_RESET_PICKUPS = "Function TAGame.GameEvent_TA.ResetPickups"
FUNCTION_GAMEEVENT_BEGIN_PLAY = "Function TAGame.GameEvent_Soccar_TA.PostBeginPlay"
FUNCTION_GAME_EVENT_ACTIVE_TICK = "Function TAGame.GameEvent_Soccar_TA.Active.Tick"
FUNCTION_GAME_VIEWPORT_CLIENT_TICK = "Function Engine.GameViewportClient.Tick"
FUNCTION_GAME_EVENT_DESTROYED = "Function TAGame.GameEvent_Soccar_TA.Destroyed"

CLASS_CORE_OBJECT = "Class Core.Object"

GREEN = '\033[92m' # Texte vert
RED = '\033[91m' # Texte rouge
BLUE = '\033[94m' # Texte bleu
YELLOW = '\033[93m' # Texte jaune
END = '\033[0m'    # Réinitialiser le style

# Event list

ON_FUNCTION_HOOKED="on_function_called"

DEFAULT_CONFIG = {
    "gnames_offset": None,
    "gobjects_offset": None,
}


class RLSDK:

    def __init__(self, hook_player_tick=False, pid=None):
        
        self.pid = pid

        self.config = DEFAULT_CONFIG
        
        try:
            self.pm = pymem.Pymem(self.pid if self.pid else PROCESS_NAME)
            self.frida = frida.attach(self.pid if self.pid else PROCESS_NAME)
        except:
            raise Exception(Fore.RED + "Rocket League not found. Make sure Rocket League is running." + END)


        # open sdk_config.json file to read offsets
        
        try:
            with open("sdk_config.json", "r") as file:
                self.config = json.load(file)

                if self.config["gnames_offset"]:
                    self.g_names_offset = self.config["gnames_offset"]
          
                if self.config["gobjects_offset"]:
                    self.g_object_offset = self.config["gobjects_offset"]
        except:
            # create sdk_config.json file if it doesn't exist
            with open("sdk_config.json", "w") as file:
                json.dump(DEFAULT_CONFIG, file, indent=4)
        
    

        if self.config["gnames_offset"] == None or self.config["gobjects_offset"] == None:
            try:
                self.resolve_offsets()
            except:
                raise Exception(Fore.RED + "Offsets not found. Make sure Rocket League is running. If Rocket League is running, game memory structure may have changed and can't be scanned. Please try to obtain them by your own and update sdk_config.json" + END)
            
            # save offsets to sdk_config.json
            
            with open("sdk_config.json", "w") as file:
                json.dump(self.config, file, indent=4)
            
        else:
            print(Fore.GREEN + "Offsets found in sdk_config.json" + END)

        self.event = Event()

        self.index_indexed_gnames = {}
        self.gnames = {}

        self.static_classes = {}
        self.static_functions = {}

        self.scan_result = []
        self.scan_response_received_event = threading.Event()


        try:
            self.load_gnames()
            self.map_objects()
            
            if len(self.gnames) == 0 or len(self.static_classes) == 0 or len(self.static_functions) == 0:
                raise Exception("GNames or mapping objects not found")

        except:
            print(Fore.RED + "Error while loading GNames and mapping objects. Trying to resolve offsets" + END)
           # If an error occurs, offset may be wrong, try to resolve them again
            try:
                self.resolve_offsets()
                self.load_gnames()
                self.map_objects()
                
                with open("sdk_config.json", "w") as file:
                    json.dump(self.config, file, indent=4)
            except:
                raise Exception(Fore.RED + "Error while loading GNames and mapping objects. Make sure Rocket League is running." + END)

            

        self.process_event_address = self.get_process_event_address()
        self.current_game_event = None

        if self.process_event_address == None:
            print(Fore.RED + "ProcessEvent address not found. Make sure Rocket League is running." + END)
            return

        print("ProcessEvent Address: " + hex(self.process_event_address))
        print(Fore.GREEN + "ProcessEvent address found: " + Fore.BLUE + hex(self.process_event_address) + END)
       
        print(Fore.YELLOW + "Injecting Frida script..." + END)

        self.frida_script = self.frida.create_script(frida_script)
        self.frida_script.load()
        self.frida_script.on('message', self.on_frida_message)

        # send process event address to frida
        self.frida_script.post({"type": "process_event_address", "address": self.process_event_address})

        self.hook_function(FUNCTION_BOOST_PICKED_UP)
        self.hook_function(FUNCTION_BOOST_RESPAWN)
        self.hook_function(FUNCTION_ROUND_ACTIVE_BEGIN)
        self.hook_function(FUNCTION_ROUND_ACTIVE_END)
        self.hook_function(FUNCTION_RESET_PICKUPS)
        self.hook_function(FUNCTION_GAMEEVENT_BEGIN_PLAY)
        # self.hook_function(FUNCTION_GAME_EVENT_ACTIVE_TICK)
        self.hook_function(FUNCTION_KEY_PRESS, args_map=[(2, "bytes", "key_params", 0x1c)])
        self.hook_function(FUNCTION_GAME_VIEWPORT_CLIENT_TICK)
        self.hook_function(FUNCTION_GAME_EVENT_DESTROYED)

        # player tick is conditional because it's called every frame, we don't want hook it if developer doesn't need it

        if hook_player_tick:
            self.hook_function(FUNCTION_PLAYER_TICK, args_map=[(2, "float", "deltatime")])


        self.event.subscribe(EventTypes.ON_HOOKED_FUNCTION, self.on_function_called)

        self.field = Field(self)
        
        print(Fore.GREEN + "SDK initialized" + END)
      
    # ==========================================================
    # ================     Offsets finding     =================
    # ==========================================================

        
    def resolve_offsets(self):

        print(Fore.YELLOW + "Finding GNames offset..." + END)
        try:
            self.g_names_offset = self.resolve_gnames_offset()
            self.config["gnames_offset"] = self.g_names_offset
        except:
            raise Exception("GNames offset not found")


        print(Fore.GREEN + "GNames offset found at " + Fore.BLUE + hex(self.g_names_offset) + END)
        
        print(Fore.YELLOW + "Finding GObjects offset..." + END)
        
        try:
            self.g_object_offset = self.resolve_gobjects_offset()
            self.config["gobjects_offset"] = self.g_object_offset
        except:
            raise Exception(Fore.RED + "GObjects offset not found" + END)
        
        print(Fore.GREEN + "GObjects offset found at " + Fore.BLUE + hex(self.g_object_offset) + END)

        
        
        
    def resolve_gobjects_offset(self):
        # Pattern recherché
        pattern = rb'\xE8....\x8B\x5D\xAF'
        
        # Trouver l'adresse de base du pattern
        base_address = self.pm.pattern_scan_all(pattern, return_multiple=False)
        if base_address is None:
            return None

        # Calcul des différents offsets pour atteindre l'adresse finale
        # Lire l'offset relatif à partir de l'adresse de base + 1 et ajouter à base_address
        relative_offset = self.pm.read_int(base_address + 1)
        intermediate_address = base_address + 1 + relative_offset + 4  # +4 pour la taille de l'int lu

        # Lire l'offset relatif à partir du nouvel emplacement + 0x65 et ajouter à l'adresse intermédiaire
        final_relative_offset = self.pm.read_int(intermediate_address + 0x65 + 3)
        final_address = intermediate_address + 0x65 + 3 + final_relative_offset + 4  # +4 pour la taille de l'int lu
        
        if not final_address:
            raise Exception("GObjects offset not found")

        return final_address - self.pm.base_address

    def resolve_gnames_offset(self):
        # Pattern recherché
        pattern = rb'\x75.\xE8....\x48\xC7\xC7'
        
        # Trouver l'adresse de base du pattern
        base_address = self.pm.pattern_scan_all(pattern, return_multiple=False)
        if base_address is None:
            return None

        # Calcul des différents offsets pour atteindre l'adresse finale
        # Lire l'offset relatif à partir de l'adresse de base + 3 et ajouter à base_address
        relative_offset = self.pm.read_int(base_address + 3)
        intermediate_address = base_address + 3 + relative_offset + 4  # +4 pour la taille de l'int lu

        # Lire l'offset relatif à partir du nouvel emplacement + 0x2F et ajouter à l'adresse intermédiaire
        final_relative_offset = self.pm.read_int(intermediate_address + 0x2F + 3)
        final_address = intermediate_address + 0x2F + 3 + final_relative_offset + 4  # +4 pour la taille de l'int lu
        
        if not final_address:
            raise Exception("GNames offset not found")

        return final_address - self.pm.base_address


    def get_provider(self):
        # Pattern recherché
        pattern = rb'\xBA\xFA\x02\x00\x00\x48\x89\x05'
        
        # Trouver l'adresse de base du pattern
        base_address = self.pm.pattern_scan_all(pattern, return_multiple=False)
        if base_address is None:
            return None

        # Calcul des différents offsets pour atteindre l'adresse finale
        # Lire l'offset relatif à partir de l'adresse de base + 8 et ajouter à base_address
        relative_offset = self.pm.read_int(base_address + 8)
        final_address = base_address + 8 + relative_offset + 4  # +4 pour la taille de l'int lu

        # Lire l'adresse du UObjectProvider à partir de l'adresse calculée
        provider_address = self.pm.read_ulonglong(final_address)
        if not provider_address:
            return None

        # La structure commence à provider_address + 0xD8
        tarray_base_address = provider_address + 0xD8

        # Création et retour de l'objet TArray
        tarray = TArray(tarray_base_address, UObject, sdk=self)
        
        return tarray
    
    
    
        
    def load_gnames(self):

        print(Fore.YELLOW + "Loading GNames..." + END)
        gnames_entries_tarray = self.get_gnames_entries_tarray()
        print(Fore.GREEN + "GNames count: " + Fore.BLUE + str(len(gnames_entries_tarray)) + END)
        
        
        for gname_entry in tqdm(gnames_entries_tarray):

            if not gname_entry.address:
                continue

            self.gnames[gname_entry.get_index()] = gname_entry.get_name()
            

        print(Fore.GREEN + "GNames loaded" + END)

    def map_objects(self):
        print(Fore.YELLOW + "Mapping objects..." + END)
        gobjects_tarray = self.get_gobjects_tarray()
        for gobject in tqdm(gobjects_tarray.get_items()):
            try:
                if not gobject.address:
                    continue
                # if full_name content "Class " then it's a UClass

                full_name = gobject.get_full_name() 
                
                if "Class " in full_name:
                    self.static_classes[full_name] = UClass(gobject.address, sdk=self)
                elif "Function " in full_name:
                    self.static_functions[full_name] = UFunction(gobject.address, sdk=self)
            except:
                continue
        
        
        print(Fore.GREEN + "UClasses: " + Fore.BLUE + str(len(self.static_classes)) + END)
        print(Fore.GREEN + "UFunctions: " + Fore.BLUE + str(len(self.static_functions)) + END)
    
    # ==========================================================
    # ================ INTERNAL EVENT HANDLING =================
    # ==========================================================
        

    def on_function_called(self, event: EventFunctionHooked):

        function_name = event.function.get_full_name()

        if function_name == FUNCTION_BOOST_PICKED_UP:
           
            pickup = VehiclePickupBoost(int(event.args['caller'], 16), sdk=self)
    
            boostpad = self.field.find_boostpad_from_pickup(pickup)
      
            if boostpad:
                boostpad.is_active = False
                boostpad.pickup = pickup
                boostpad.picked_up_time = time.time()
                
                
                # update boostpad position to make sure it's accurate (because the pickup is not always at the same position according the map)
                
                self.field.update_boostpad_from_pickup(boostpad, pickup)
              
                self.event.fire(EventTypes.ON_BOOSTPAD_CHANGED, EventBoostPadChanged(boostpad))

        elif function_name == FUNCTION_BOOST_RESPAWN:
         
            pickup = VehiclePickupBoost(int(event.args['caller'], 16), sdk=self)
            boostpad = self.field.find_boostpad_from_pickup(pickup)
            

            if boostpad:
                boostpad.is_active = True
                boostpad.pickup = pickup
                boostpad.picked_up_time = None
                
                self.field.update_boostpad_from_pickup(boostpad, pickup)

                self.event.fire(EventTypes.ON_BOOSTPAD_CHANGED, EventBoostPadChanged(boostpad))
                
        
        elif function_name == FUNCTION_PLAYER_TICK:
            
            self.event.fire(EventTypes.ON_PLAYER_TICK, EventPlayerTick(event.args['deltatime']))

        elif function_name == FUNCTION_ROUND_ACTIVE_BEGIN:
            self.event.fire(EventTypes.ON_ROUND_ACTIVE_STATE_CHANGED, EventRoundActiveStateChanged(True))


        elif function_name == FUNCTION_ROUND_ACTIVE_END:
            self.event.fire(EventTypes.ON_ROUND_ACTIVE_STATE_CHANGED, EventRoundActiveStateChanged(False))

        elif function_name == FUNCTION_RESET_PICKUPS:
            self.event.fire(EventTypes.ON_RESET_PICKUPS, EventResetPickups())
            self.field.reset_boostpads()
        elif function_name == FUNCTION_GAMEEVENT_BEGIN_PLAY:
            self.event.fire(EventTypes.ON_GAME_EVENT_STARTED, EventGameEventStarted())
        elif function_name == FUNCTION_KEY_PRESS:
            params = event.args['key_params']
          
            data_bytes = bytes.fromhex(params)
            fname_entry_id = int.from_bytes(data_bytes[4:8], byteorder='little')
            key_name = self.gnames[fname_entry_id]
            ev = EventKeyPressed(data_bytes, key_name)

            self.event.fire(EventTypes.ON_KEY_PRESSED, ev)
        # elif function_name == FUNCTION_GAME_EVENT_ACTIVE_TICK:

        #     viewport = GameViewportClient(int(event.args['caller'], 16), sdk=self)
        #     self.current_game_event = viewport.get_game_event()
        #     print(self.current_game_event.is_round_active())
        elif function_name == FUNCTION_GAME_VIEWPORT_CLIENT_TICK:
            viewport = GameViewportClient(int(event.args['caller'], 16), sdk=self)
            self.current_game_event = viewport.get_game_event()

        elif function_name == FUNCTION_GAME_EVENT_DESTROYED:
            self.current_game_event = None
            self.event.fire(EventTypes.ON_GAME_EVENT_DESTROYED, EventGameEventDestroyed())

   
    # ==========================================================
    # ===================== DEBUG METHODS ======================
    # ==========================================================


    def scan_functions(self, duration=10):
        print("Scanning functions...")
        
        self.scan_response_received_event.clear()
        self.frida_script.post({"type": "scan_functions", "duration": duration})
        received = self.scan_response_received_event.wait(duration + 10)
        if received:
            print("Scan result received.")
            return self.scan_result
        else:
            print("Scan timed out.")
            return None

    # ==========================================================
    # ================ EXTRACTION METHODS ======================
    # ==========================================================

    def extract_classes(self):
        # write all classes name to a file with their address
        print("Extracting classes...")
        filename = "classes.txt"
        with open(filename, "w") as file:
            for class_name, class_object in self.static_classes.items():
                file.write(hex(class_object.address) + " : " + class_name + "\n")
        print("Classes extracted to " + filename)


    def extract_functions(self):
        # write all functions name to a file with their address
        print("Extracting functions...")
        filename = "functions.txt"
        with open(filename, "w") as file:
            for function_name, function_object in self.static_functions.items():
                file.write(hex(function_object.address) + " : " + function_name + "\n")
        print("Functions extracted to " + filename)

    # ==========================================================
    # ================ FRIDA HOOKING METHODS ===================
    # ==========================================================

    def on_frida_message(self, message, data):
  
        if message['type'] == 'send':
            payload = message['payload']
            if payload.get('type') == 'hooked_function_fired':
                function = UFunction(int(payload.get('address'), 16), sdk=self)
                
                self.event.fire(EventTypes.ON_HOOKED_FUNCTION, EventFunctionHooked(function, payload.get('args')))
        
            if payload.get('type') == 'scan_result':
                for f in payload.get('functions'):
                    function_address = int(f, 16)
                    self.scan_result.append(UFunction(function_address, sdk=self))
                    self.scan_response_received_event.set()
            elif payload.get('type') == 'log':
                print(Fore.MAGENTA + "Frida log: " + END + payload.get('message'))
           

        else:
            print("Received message:", message)

    
    def hook_function(self, function_name, args_map=[]):

        function_address = self.find_static_function(function_name).address
        if function_address:
            self.frida_script.post({"type": "hook_function", "address": function_address, "name": function_name, "args_map": args_map})
        else:
            pass

    def get_process_event_address(self):
        core_object = self.find_static_class(CLASS_CORE_OBJECT)
        if core_object:
            print("Core Object Address: " + hex(core_object.address))
            vtable_address = self.pm.read_ulonglong(core_object.address)
            return self.pm.read_ulonglong(vtable_address + (0x8 * 67))
        return None


    # ==========================================================
    # ===================== Accessors ==========================
    # ==========================================================
    
    def get_game_event(self):
        return self.current_game_event
    
    def get_field(self):
        return self.field
    

    def get_gobjects_tarray(self):
        return TArray(self.pm.base_address + self.g_object_offset, UObject, sdk=self)  # Remplacer UObject par la classe appropriée

    def get_gnames_entries_tarray(self):
        return TArray(self.pm.base_address + self.g_names_offset, FNameEntry, sdk=self)
    

    def get_pm(self):
        return self.pm
    
    
    # ==========================================================
    # =====================   Methods  =========================
    # ==========================================================
    

    def get_name(self, index):
        return self.gnames.get(index)
        
        
    def find_static_function(self, function_name):
        return self.static_functions.get(function_name)
    
    def find_static_class(self, class_name):
        return self.static_classes.get(class_name)
    
    
    # Use to read cheat engine pointer offsets if needed
    def get_offsets_final_address(self, offsets):
        if self.pm != None:
            base_address = self.pm.base_address
            for offset in offsets:
                base_address = self.pm.read_ulonglong(base_address + offset)
            return base_address
        
