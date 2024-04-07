import pymem
from typing import List, Tuple
import ctypes
import frida
import time
import threading

PROCESS_NAME = "RocketLeague.exe"

FUNCTION_PICKED_UP = "Function TAGame.VehiclePickup_TA.OnPickUp"
FUNCTION_PLAYER_TICK = "Function Engine.PlayerController.PlayerTick"
FUNCTION_KEY_PRESS = "Function TAGame.GameViewportClient_TA.HandleKeyPress"
FUNCTION_BALL_CAR_TOUCH= "Function TAGame.Ball_TA.EventCarTouch"
FUNCTION_SET_VEHICLE_INPUT = "Function TAGame.Car_TA.SetVehicleInput"
FUNCTION_PICKUP_TOUCH = "Function TAGame.VehiclePickup_TA.Touch"

CLASS_CORE_OBJECT = "Class Core.Object"

GREEN = '\033[92m' # Texte vert
RED = '\033[91m' # Texte rouge
BLUE = '\033[94m' # Texte bleu
YELLOW = '\033[93m' # Texte jaune




END = '\033[0m'    # Réinitialiser le style

class RLSDK:

    def __init__(self):
        try:
            self.pm = pymem.Pymem(PROCESS_NAME)
            self.frida = frida.attach(PROCESS_NAME)
        except:
            print("Error opening RocketLeague.exe")
            return
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

        self.frida_script = self.frida.create_script(open("process_event_hook.js").read())
        self.frida_script.load()
        self.frida_script.on('message', self.on_frida_message)

        # send process event address to frida
        self.frida_script.post({"type": "process_event_address", "address": self.process_event_address})



        self.hook_function("Function TAGame.VehiclePickup_Boost_TA.Idle.BeginState")
        self.hook_function("Function TAGame.VehiclePickup_Boost_TA.Idle.EndState")
        


        print("RLSDK initialized")


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
        


    def test(self):
        print("TRIGGERED")


    def on_frida_message(self, message, data):


        if message['type'] == 'send':
            payload = message['payload']
            if payload.get('type') == 'hooked_function_fired':
                print("Hooked function fired:", payload.get('name'))
            if payload.get('type') == 'scan_result':
                for f in payload.get('functions'):
                    function_address = int(f, 16)
                    self.scan_result.append(UFunction(function_address, sdk=self))
                    self.scan_response_received_event.set()

           
        elif message['type'] == 'log':

            print(f"{GREEN}Log from Frida script:{END} {message.get('payload')}")
        else:
            print("Received message:", message)


    
    def hook_function(self, function_name):

        function_address = self.find_static_function(function_name).address
        if function_address:
            print("Function found at: " + hex(function_address))
            self.frida_script.post({"type": "hook_function", "address": function_address, "name": function_name})
        else:
            print("Function not found")
        


    def get_pm(self):
        return self.pm


    def get_offsets_final_address(self, offsets):
        if self.pm != None:
            base_address = self.pm.base_address
        
            for offset in offsets:
                base_address = self.pm.read_ulonglong(base_address + offset)
            return base_address
        
    def get_game_event(self):
        offsets = [0x023157A0, 0x200, 0x458, 0x278, 0x20, 0x118, 0x78]
        game_event_address = self.get_offsets_final_address(offsets)
        return GameEvent(game_event_address, sdk=self)
    

    def get_gobjects_tarray(self):
        return TArray(self.pm.base_address + self.g_object_offset, UObject, sdk=self)  # Remplacer UObject par la classe appropriée

    def get_gnames_entries_tarray(self):
        return TArray(self.pm.base_address + self.g_names_offset, FNameEntry, sdk=self)
    

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
    

    def get_process_event_address(self):
        core_object = self.find_static_class(CLASS_CORE_OBJECT)
        if core_object:
            print("Core Object Address: " + hex(core_object.address))
            vtable_address = self.pm.read_ulonglong(core_object.address)
            return self.pm.read_ulonglong(vtable_address + (0x8 * 67))
        return None

    


    

    
    # def get_all_instances_of(self, class_name, cast_class):
    #     object_instances = []
    #     for address, gobject in self.address_indexed_objects.items():
    #         if not address:
    #             continue
     
    #         if gobject and gobject.is_a(class_name):
    #             if "Default__" not in gobject.get_full_name():
    #                 object_instances.append(cast_class(address))

    #     return object_instances
    
    
class Pointer:
  def __init__(self, address, *, sdk=None):

        if(address == None):
           raise ValueError("Address is None")

        self.address = address
        self.sdk = sdk
       








class UObject(Pointer):
    size = 0x0060

    def get_name(self):
        return self.sdk.get_fname_string(self.address + 0x0048)
    
    def get_index(self):
        return self.sdk.pm.read_int(self.address +0x0038)
    
    def get_outer(self):
        try:
            outer = UObject(self.sdk.pm.read_ulonglong(self.address + 0x0040), sdk=self.sdk)
            return outer
        except:
            return None
    
    def get_class(self):
        return UClass(self.sdk.pm.read_ulonglong(self.address + 0x0050), sdk=self.sdk)
        
    def get_full_name(self):
        full_name = self.get_name()

        # Traverse les objets "Outer"
        outer = self.get_outer()
        if outer:

            while outer is not None and outer.address != 0: 
                full_name = f"{outer.get_name()}.{full_name}"
                outer = outer.get_outer()

            

            # Ajoute le nom de la classe
            class_name = self.get_class().get_name() if self.get_class() is not None else "UnknownClass"
            full_name = f"{class_name} {full_name}"

            return full_name
        else:
            return full_name

    

    def is_a(self, class_name):
        current_class = self.get_class()
        while current_class is not None:
            if current_class.get_full_name() == class_name:
                return True
            # Assure-toi que get_super_field renvoie le parent correct, et non un UField générique
            current_class = current_class.get_super_field() if isinstance(current_class, UClass) else None
        return False






class UField(UObject):
    size = 0x0070

    def get_next(self):
        # Lire l'adresse du champ suivant ('Next') depuis la mémoire
        next_field_addr = self.sdk.pm.read_ulonglong(self.address + 0x0060)
        if next_field_addr != 0:  # Vérifie si l'adresse est non nulle
            return UField(next_field_addr, sdk=self.sdk)  # Ou une sous-classe appropriée si nécessaire
        return None





class UFunction(UField):
    size = 0x0160





class UClass(UObject):
    size = 0x03B8


    def get_super_field(self):
        # Lire l'adresse du SuperField depuis la mémoire
        super_field_addr = self.sdk.pm.read_ulonglong(self.address + 0x0080)  # Remplace 'offset_SuperField' par l'offset réel
        if super_field_addr != 0:  # Vérifie si l'adresse est non nulle
            return UField(super_field_addr, sdk=self.sdk)  # Ou une sous-classe appropriée si nécessaire
        return None

class GameEvent(UObject):
    def __init__(self, address = None, sdk=None):
        super().__init__(address, sdk=sdk)
        self.balls_offset = 0x0880
        self.cars_offset = 0x0350
        self.pris_offset = 0x0340
        self.teams_offset = 0x0748
        self.players_offset = 0x0330


    def get_balls(self):
        game_balls_tarray_address = self.address + self.balls_offset
        return TArray(game_balls_tarray_address, Ball, sdk=self.sdk).get_items()
    
    def get_cars(self):
        game_cars_tarray_address = self.address + self.cars_offset
        return TArray(game_cars_tarray_address, Car, sdk=self.sdk).get_items()
    
    def get_pris(self):
        game_pris_tarray_address = self.address + self.pris_offset
        return TArray(game_pris_tarray_address, PRI, sdk=self.sdk).get_items()
    
    def get_teams(self):
        game_teams_tarray_address = self.address + self.teams_offset
        return TArray(game_teams_tarray_address, Team, sdk=self.sdk).get_items()
    
    def get_players(self):
        game_players_tarray_address = self.address + self.players_offset
        return TArray(game_players_tarray_address, Controller, sdk=self.sdk).get_items()
    
    def get_game_time(self):
        return self.sdk.pm.read_int(self.address + 0x07D4)
    
    def get_warmup_time(self):
        return self.sdk.pm.read_int(self.address + 0x07D8)
    
    def get_max_score(self):
        return self.sdk.pm.read_int(self.address + 0x07DC)
    
    def get_seconds_remaining(self):
        return self.sdk.pm.read_int(self.address + 0x0810)
    
    def get_total_game_time_played(self):
        return self.sdk.pm.read_float(self.address + 0x0818)
    
    def get_overtime_played(self):
        return self.sdk.pm.read_float(self.address + 0x081C)

    def is_round_active(self):
        return self.sdk.pm.read_int(self.address + 0x0868) & 1
    
    def is_play_replays(self):
        return (self.sdk.pm.read_int(self.address + 0x0868) >> 1) & 1
    
    def is_ball_has_been_hit(self):
        return (self.sdk.pm.read_int(self.address + 0x0868) >> 2) & 1
    
    def is_overtime(self):
        return (self.sdk.pm.read_int(self.address + 0x0868) >> 3) & 1
    
    def is_unlimited_time(self):
        return (self.sdk.pm.read_int(self.address + 0x0868) >> 4) & 1
    
    def is_no_contest(self):
        return (self.sdk.pm.read_int(self.address + 0x0868) >> 5) & 1
    
    def is_disable_goal_delay(self):
        return (self.sdk.pm.read_int(self.address + 0x0868) >> 6) & 1
    
    def is_show_no_scorer_goal_message(self):
        return (self.sdk.pm.read_int(self.address + 0x0868) >> 7) & 1
    
    def is_match_ended(self):
        return (self.sdk.pm.read_int(self.address + 0x0868) >> 8) & 1
    
    def is_show_intro_scene(self):
        return (self.sdk.pm.read_int(self.address + 0x0868) >> 9) & 1
    
    def is_club_match(self):
        return (self.sdk.pm.read_int(self.address + 0x0868) >> 10) & 1
    
    def is_can_drop_online_rewards(self):
        return (self.sdk.pm.read_int(self.address + 0x0868) >> 11) & 1
    
    def is_allow_honor_duels(self):
        return (self.sdk.pm.read_int(self.address + 0x0868) >> 12) & 1
    
    def get_match_winner(self):
        team_address = self.sdk.pm.read_ulonglong(self.address + 0x08D8)
        return Team(team_address, sdk=self.sdk)
    
    def get_game_winner(self):
        team_address = self.sdk.pm.read_ulonglong(self.address + 0x08D0)
        return Team(team_address, sdk=self.sdk)
    
    def get_mvp(self):
        pri_address = self.sdk.pm.read_ulonglong(self.address + 0x08E8)
        return PRI(pri_address, sdk=self.sdk)
    
    def get_fastest_goal_player(self):
        pri_address = self.sdk.pm.read_ulonglong(self.address +  0x08F0)
        return PRI(pri_address, sdk=self.sdk)
    
    def get_slowest_goal_player(self):
        pri_address = self.sdk.pm.read_ulonglong(self.address + 0x08F8)
        return PRI(pri_address, sdk=self.sdk)
    
    def get_furthest_goal_player(self):
        pri_address = self.sdk.pm.read_ulonglong(self.address + 0x0900)
        return PRI(pri_address, sdk=self.sdk)
    
    def get_fastest_goal_speed(self):
        return self.sdk.pm.read_float(self.address + 0x0908)
    
    def get_slowest_goal_speed(self):
        return self.sdk.pm.read_float(self.address + 0x090C)
    
    def get_furthest_goal(self):
        return self.sdk.pm.read_float(self.address + 0x0910)
    
    def get_scoring_player(self):
        pri_address = self.sdk.pm.read_ulonglong(self.address + 0x0918)
        return PRI(pri_address, sdk=self.sdk)
    
    def get_round_num(self):
        return self.sdk.pm.read_int(self.address + 0x0920)
    
    def get_game_owner(self):
        pri_address = self.sdk.pm.read_ulonglong(self.address + 0x0430)
        return PRI(pri_address, sdk=self.sdk)
    
    def get_count_down_time(self):
        return self.sdk.pm.read_int(self.address + 0x02A0)
    


class TArray(Pointer):

    size = 0x10

    def __init__(self, address, class_type, sdk=None):
        super().__init__(address, sdk=sdk)
        self.class_type = class_type

    def get_count(self):
        return self.sdk.pm.read_int(self.address + 0x8)
    
    def get_max(self):
        return self.sdk.pm.read_int(self.address + 0xC)

    def get_data_address(self):
        return self.sdk.pm.read_ulonglong(self.address)
    
    def get_items(self):
        data_address = self.get_data_address()
        count = self.get_count()
        items = []
        for i in range(count):
            item_address = self.sdk.pm.read_ulonglong(data_address + i * 0x8)
            items.append(self.class_type(item_address, sdk=self.sdk))
        return items
    
    def get_item(self, index):
        data_address = self.get_data_address()
        item_address = self.sdk.pm.read_ulonglong(data_address + index * 0x8)
        return self.class_type(item_address, sdk=self.sdk)

class FVector(Pointer):
    size = 0x0C

    def get_x(self):
        return self.sdk.pm.read_float(self.address)
    
    def get_y(self):
        return self.sdk.pm.read_float(self.address + 0x4)
    
    def get_z(self):
        return self.sdk.pm.read_float(self.address + 0x8)
    
    def get_xyz(self) -> Tuple[float, float, float]:
        return self.get_x(), self.get_y(), self.get_z()
    
class FRotator(Pointer):
    size = 0x0C

    def get_pitch(self):
        return self.sdk.pm.read_int(self.address)
    
    def get_yaw(self):
        return self.sdk.pm.read_int(self.address + 0x4)
    
    def get_roll(self):
        return self.sdk.pm.read_int(self.address + 0x8)

    
    def get_pyr(self) -> Tuple[int, int, int]:
        return self.get_pitch(), self.get_yaw(), self.get_roll()

class Actor(UObject):
    size = 0x0268

    def get_location(self) -> FVector: 
        location_address = self.address + 0x0090
        return FVector(location_address, sdk=self.sdk)
    
    def get_rotation(self) -> FRotator:
        rotation_address = self.address + 0x009C
        return FRotator(rotation_address, sdk=self.sdk)
    
    def get_velocity(self) -> FVector:
        velocity_address = self.address + 0x01A8
        return FVector(velocity_address, sdk=self.sdk)
    
    def get_angular_velocity(self) -> FVector:
        angular_velocity_address = self.address + 0x01C0
        return FVector(angular_velocity_address, sdk=self.sdk)

class Ball(Actor):
    size = 0x0A48

class FString(Pointer):
    def get_string(self):
        # Lire l'adresse du tableau de caractères
        array_data_address = self.sdk.pm.read_ulonglong(self.address)
        # Lire le nombre de caractères
        array_count = self.sdk.pm.read_int(self.address + 0x8)

        # Créer une chaîne de caractères vide
        result = ""

        # Lire chaque caractère de la chaîne
        for i in range(array_count - 1):  # -1 car il y a souvent un caractère null de terminaison
            char = self.sdk.pm.read_ushort(array_data_address + (i * 2))  # lire 2 octets à la fois
            result += chr(char)

        return result
    
class PlayerReplicationInfo(Pointer):
    size = 0x0410

    def get_player_name(self):
        player_name_address = self.address + 0x0288
        return FString(player_name_address, sdk=self.sdk).get_string()
    
    def get_team_info(self):
        team_info_address = self.sdk.pm.read_ulonglong(self.address + 0x02B0)
        return TeamInfo(team_info_address, sdk=self.sdk)
    
    def get_score(self):
        return self.sdk.pm.read_int(self.address + 0x0278)
    
    def get_deaths(self):
        return self.sdk.pm.read_int(self.address + 0x027C)

    def get_ping(self):
        bytes = self.sdk.pm.read_bytes(self.address +  0x0280, 1)
        return int.from_bytes(bytes, byteorder='little')
    
    def get_player_id(self):
        return self.sdk.pm.read_int(self.address + 0x02A8)

class PRI(PlayerReplicationInfo):
    size = 0x0BD0

    def get_car(self):
        car_address = self.sdk.pm.read_ulonglong(self.address + 0x0490)
        return Car(car_address, sdk=self.sdk)
    
    def get_ball_touches(self):
        ball_touches_address = self.address + 0x070C
        return self.sdk.pm.read_int(ball_touches_address)
    
    def get_car_touches(self):
        car_touches_address = self.address + 0x0710
        return self.sdk.pm.read_int(car_touches_address)
    
    def get_boost_pickups(self):
        boost_pickups_address = self.address + 0x0708
        return self.sdk.pm.read_int(boost_pickups_address)
    
    def get_game_event(self):
        game_event_address = self.sdk.pm.read_ulonglong(self.address + 0x0480)
        return GameEvent(game_event_address, sdk=self.sdk)
    
    def get_replicated_game_event(self):
        replicated_game_event_address = self.sdk.pm.read_ulonglong(self.address +  0x0488)
        return GameEvent(replicated_game_event_address, sdk=self.sdk)

class Pawn(Actor):
    size = 0x0514

    def get_player_info(self):
        player_info_address = self.sdk.pm.read_ulonglong(self.address + 0x0410)
        return PlayerReplicationInfo(player_info_address, sdk=self.sdk)

class BoostComponent(Pointer):
    size = 0x0368

    def get_amount(self):
        return self.sdk.pm.read_float(self.address + 0x030C)
    
    def get_max_amount(self):
        return self.sdk.pm.read_float(self.address + 0x0304)
    
    def get_consumption_rate(self):
        return self.sdk.pm.read_float(self.address + 0x0300)
    
    def get_start_amount(self):
        return self.sdk.pm.read_float(self.address + 0x0308)

class Vehicle(Pawn):
    size = 0x08A8
    
    def get_pri(self):
        pri_address = self.sdk.pm.read_ulonglong(self.address + 0x0800)
        return PRI(pri_address, sdk=self.sdk)   

    def get_inputs(self):
        input_address = self.address + 0x07CC
        return VehicleInputs(input_address, sdk=self.sdk)
    
    def get_boost_component(self):
        boost_component_address = self.sdk.pm.read_ulonglong(self.address + 0x0840)
        return BoostComponent(boost_component_address, sdk=self.sdk)

class Car(Vehicle):
    size = 0x0B48

    def get_attacker_pri(self):
        pri_address = self.sdk.pm.read_ulonglong(self.address + 0x09E0)
        return PRI(pri_address, sdk=self.sdk)

class FColor(Pointer):
    size = 0x04

    def get_b(self):
        return self.sdk.pm.read_uchar(self.address)
    
    def get_g(self):
        return self.sdk.pm.read_uchar(self.address + 0x1)
    
    def get_r(self):
        return self.sdk.pm.read_uchar(self.address + 0x2)
    
    def get_a(self):
        return self.sdk.pm.read_uchar(self.address + 0x3)
    
    def get_rgba(self) -> Tuple[int, int, int, int]:
        return self.get_r(), self.get_g(), self.get_b(), self.get_a()

class TeamInfo(Pointer):
    size = 0x0290

    def get_name(self):
        team_name_address = self.address + 0x0268
        return FString(team_name_address, sdk=self.sdk).get_string()
    
    def get_size(self):
        return self.sdk.pm.read_int(self.address + 0x0278)
    
    def get_score(self):
        return self.sdk.pm.read_int(self.address + 0x027C)
    
    def get_index(self):
        return self.sdk.pm.read_int(self.address + 0x0280)
    
    def get_color(self):
        color_address = self.address + 0x0284
        return FColor(color_address, sdk=self.sdk).get_rgba()

class Team(TeamInfo):
    size = 0x0468

    def get_members(self):
        members_address = self.address + 0x0318
        return TArray(members_address, PRI, sdk=self.sdk).get_items()

class Controller(Pointer):
    size = 0x0474

    def get_player_num(self):
        return self.sdk.pm.read_int(self.address + 0x0290)

class VehicleInputs(Pointer):
    size = 0x0020

    def __init__ (self, address, sdk=None):
        super().__init__(address, sdk=sdk)

        self.data = self.sdk.pm.read_bytes(address, self.size)
        # set all input from data bytes without read memory
        self.throttle = ctypes.c_float.from_buffer_copy(self.data, 0).value
        self.steer = ctypes.c_float.from_buffer_copy(self.data, 4).value
        self.pitch = ctypes.c_float.from_buffer_copy(self.data, 8).value
        self.yaw = ctypes.c_float.from_buffer_copy(self.data, 12).value
        self.roll = ctypes.c_float.from_buffer_copy(self.data, 16).value
        self.dodge_forward = ctypes.c_float.from_buffer_copy(self.data, 20).value
        self.dodge_right = ctypes.c_float.from_buffer_copy(self.data, 24).value
        # Next inputs are encoded on a single int_32 value (4 bytes)
        self.inputs = ctypes.c_uint32.from_buffer_copy(self.data, 28).value
        self.handbrake = self.inputs & 1
        self.jump = (self.inputs >> 1) & 1
        self.activate_boost = (self.inputs >> 2) & 1
        self.holding_boost = (self.inputs >> 3) & 1
        self.jumped = (self.inputs >> 4) & 1
        self.grab = (self.inputs >> 5) & 1
        self.button_mash = (self.inputs >> 6) & 1
    pass



class FNameEntry(Pointer):
    size = 0x0400

    def get_name(self):
        name_address = self.address + 0x0018
        try:
            bytes = self.sdk.pm.read_bytes(name_address, 0x400)
        except:
            return "None"
        return ctypes.wstring_at(bytes)
    
    def get_index(self):
        return self.sdk.pm.read_int(self.address + 0x0008)


# struct FName
# {
# public:
# 	using ElementType = const wchar_t;
# 	using ElementPointer = ElementType*;

# private:
# 	int32_t			FNameEntryId;									// 0x0000 (0x04)
# 	int32_t			InstanceNumber;									// 0x0004 (0x04)


class FName(Pointer):
    size = 0x08

    def get_name_entry_id(self):
        if self.address == 0:
            return -1
        try:
            return self.sdk.pm.read_int(self.address)
        except:
            return -1
    
    def get_instance_number(self):
        try:
            return self.sdk.pm.read_int(self.address + 0x4)
        except:
            return -1

    def get_name_entry(self):
        index = self.get_name_entry_id()
        if index == -1:
            return None
        
        entry = self.sdk.get_gname_by_index(index)
        if entry:
            return FNameEntry(entry.address, sdk=self.sdk)
        return None
    


    def get_name(self):
        name_entry = self.get_name_entry()
        if name_entry:
            return name_entry.get_name()
        return None

    


class BoostPad(Actor):

    def get_amount(self):
        return self.sdk.pm.read_float(self.address + 0x02F0)



