import pymem

import ctypes
import frida
import time
import threading
from typing import Callable, Any, Protocol
from .event_handling import Event
from .events import  EventFunctionHooked, EventTypes, EventPlayerTick, EventRoundActiveStateChanged, EventResetPickups, EventGameEventStarted
from .game_objects import UClass, UFunction, GameEvent, TArray, UObject, FNameEntry, FName, Field, VehiclePickupBoost
from .frida_script import frida_script
import struct

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

CLASS_CORE_OBJECT = "Class Core.Object"

GREEN = '\033[92m' # Texte vert
RED = '\033[91m' # Texte rouge
BLUE = '\033[94m' # Texte bleu
YELLOW = '\033[93m' # Texte jaune
END = '\033[0m'    # Réinitialiser le style

# Event list

ON_FUNCTION_HOOKED="on_function_hooked"





class RLSDK:

    def __init__(self, hook_player_tick=False):

        try:
            self.pm = pymem.Pymem(PROCESS_NAME)
            self.frida = frida.attach(PROCESS_NAME)
        except:
            print("Error opening RocketLeague.exe")
            return

        self.event = Event()
        
        self.g_names_offset = 0x2429230
        self.g_object_offset = 0x2429278

        self.address_indexed_gnames = {}
        self.name_indexed_gnames = {}
        self.index_indexed_gnames = {}

        self.static_classes = {}
        self.static_functions = {}

        self.scan_result = []
        self.scan_response_received_event = threading.Event()

        self.load_gnames()
        self.map_objects()

        self.process_event_address = self.get_process_event_address()

        if self.process_event_address == None:
            print("Process event address not found")
            return

        print("ProcessEvent Address: " + hex(self.process_event_address))
       
        print("Injecting Frida script...")

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

        # player tick is conditional because it's called every frame, we don't want hook it if developer doesn't need it

        if hook_player_tick:
            self.hook_function(FUNCTION_PLAYER_TICK, args_map=[(2, "float", "deltatime")])

        
        print("RLSDK initialized")

        self.event.subscribe(EventTypes.ON_HOOKED_FUNCTION, self.on_function_hooked)

        self.field = Field(self)
      
 


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
    # ================ INTERNAL EVENT HANDLING =================
    # ==========================================================
        

    def on_function_hooked(self, event: EventFunctionHooked):

        function_name = event.function.get_full_name()

        if function_name == FUNCTION_BOOST_PICKED_UP:

            pickup = VehiclePickupBoost(int(event.args['caller'], 16), sdk=self)
    
     
            boostpad = self.field.find_boostpad_from_pickup(pickup)
      
            if boostpad:
                boostpad.is_active = False

        elif function_name == FUNCTION_BOOST_RESPAWN:
         
            pickup = VehiclePickupBoost(int(event.args['caller'], 16), sdk=self)
            boostpad = self.field.find_boostpad_from_pickup(pickup)
            if boostpad:
                boostpad.is_active = True
        
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
           
        elif message['type'] == 'log':
            print(f"{GREEN}Log from Frida script:{END} {message.get('payload')}")
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


        
    def get_game_event(self):
        offsets = [0x023157A0, 0x200, 0x458, 0x278, 0x20, 0x118, 0x78]
        try:
            game_event_address = self.get_offsets_final_address(offsets)
        except:
            return None
        return GameEvent(game_event_address, sdk=self)
    
    def get_field(self):
        return self.field
    

    def get_gobjects_tarray(self):
        return TArray(self.pm.base_address + self.g_object_offset, UObject, sdk=self)  # Remplacer UObject par la classe appropriée

    def get_gnames_entries_tarray(self):
        return TArray(self.pm.base_address + self.g_names_offset, FNameEntry, sdk=self)
    

    def get_pm(self):
        return self.pm
    
    def load_gnames(self):

        print("Loading Gnames...")
        gnames_entries_tarray = self.get_gnames_entries_tarray()
        print("GNames count: "  + str(gnames_entries_tarray.get_count()))

        for gname_entry in gnames_entries_tarray.get_items():

            if not gname_entry.address:
                continue

            self.address_indexed_gnames[gname_entry.address] = gname_entry
            self.name_indexed_gnames[gname_entry.get_name()] = gname_entry
            self.index_indexed_gnames[gname_entry.get_index()] = gname_entry
            

        print("GNames loaded")

    def map_objects(self):
        print("Mapping objects...")
        gobjects_tarray = self.get_gobjects_tarray()
        for gobject in gobjects_tarray.get_items():
            if not gobject.address:
                continue
            # if full_name content "Class " then it's a UClass

      
            if "Class " in gobject.get_full_name():
                self.static_classes[gobject.get_full_name()] = UClass(gobject.address, sdk=self)
            elif "Function " in gobject.get_full_name():
                self.static_functions[gobject.get_full_name()] = UFunction(gobject.address, sdk=self)

        print("UClasses: " + str(len(self.static_classes)))
        print("UFunctions: " + str(len(self.static_functions)))

    def get_fname_string(self, fname_address):
        return  FName(fname_address, sdk=self).get_name()

    def get_gname_by_address(self, address):
        return self.address_indexed_gnames[address]
    
    def get_gname_by_name(self, name):
        return self.name_indexed_gnames[name]
    
    def get_gname_by_index(self, index):
        if index not in self.index_indexed_gnames:
            return None
        return self.index_indexed_gnames[index]

    def find_static_function(self, function_name):
        return self.static_functions.get(function_name)
    
    def find_static_class(self, class_name):
        return self.static_classes.get(class_name)
    
    def get_offsets_final_address(self, offsets):
        if self.pm != None:
            base_address = self.pm.base_address
        
            for offset in offsets:
                base_address = self.pm.read_ulonglong(base_address + offset)
            return base_address
        
    # def get_all_instances_of(self, class_name, cast_class):
    #     object_instances = []
    #     for address, gobject in self.address_indexed_objects.items():
    #         if not address:
    #             continue
     
    #         if gobject and gobject.is_a(class_name):
    #             if "Default__" not in gobject.get_full_name():
    #                 object_instances.append(cast_class(address))

    #     return object_instances
    
