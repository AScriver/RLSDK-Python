import ctypes
from typing import Tuple



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

    def get_goals(self):
        goals_tarray_address = self.address + 0x08A0
        return TArray(goals_tarray_address, Goal, sdk=self.sdk).get_items()

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

    def int_to_rad(self, value):
        # convert signed int (-32768 to 32767) to radian (-pi to pi)
        return value * 0.00009587379924285
    
    def get_pitch(self):
        return self.int_to_rad(self.sdk.pm.read_int(self.address))
    
    def get_yaw(self):
        return self.int_to_rad(self.sdk.pm.read_int(self.address + 0x4))
    
    def get_roll(self):
        return self.int_to_rad(self.sdk.pm.read_int(self.address + 0x8))

    
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

    def get_vehicle_sim(self):
        vehicle_sim_address = self.sdk.pm.read_ulonglong(self.address + 0x07B0)
        return VehicleSim(vehicle_sim_address, sdk=self.sdk)

    def has_wheel_contact(self):
        vehicle_sim = self.get_vehicle_sim()
        wheels = vehicle_sim.get_wheels()
        for wheel in wheels:
            if wheel.get_contact_data().get_has_contact():
                return True
        return False



class VehicleSim(UObject):
    size = 0x0164

    def get_wheels(self):
        wheels_address = self.address + 0x00A0
        return TArray(wheels_address, Wheel, sdk=self.sdk).get_items()
    
    def get_vehicle(self):
        vehicle_address = self.sdk.pm.read_ulonglong(self.address + 0x0130)
        return Vehicle(vehicle_address, sdk=self.sdk)
    
    def get_car(self):
        car_address = self.sdk.pm.read_ulonglong(self.address +0x0138)
        return Car(car_address, sdk=self.sdk)



class FWheelContactData(Pointer):
    size = 0x0050

    def get_has_contact(self):
        return self.sdk.pm.read_int(self.address) & 1
    
    def get_has_contact_with_world_geometry(self):
        return (self.sdk.pm.read_int(self.address) >> 1) & 1
    
    def get_has_contact_change_time(self):
        return self.sdk.pm.read_float(self.address + 0x4)
    
   
class Wheel(UObject):
    size = 0x01E0

    def get_contact_data(self):
        contact_data_address = self.address +  0x0160
        return FWheelContactData(contact_data_address, sdk=self.sdk)
    
    def get_wheel_index(self):
        return self.sdk.pm.read_int(self.address + 0x0158)
    



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
# 	int32_t			FNameEntryId;		// 0x0000 (0x04)
# 	int32_t			InstanceNumber;		// 0x0004 (0x04)


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
    





class FPickupData(Pointer):
    size = 0x0009

    def get_instigator(self):
        address = self.sdk.pm.read_ulonglong(self.address)
        return Car(address, sdk=self.sdk)
    
    def get_picked_up(self):
        return self.sdk.pm.read_int(self.address + 0x8) & 1



class VehiclePickup(Actor):
    def get_pickup_data(self):
        return FPickupData(self.address + 0x02A8, sdk=self.sdk)

class VehiclePickupBoost(VehiclePickup):
    def get_boost_amount(self):
        return self.sdk.pm.read_float(self.address + 0x02F0)
    
    def get_boost_type(self):
        return self.sdk.pm.read_uchar(self.address + 0x0300)
    


# Following classes are not pointing to any memory address, they are just data containers
    

class Field():
    def __init__(self, sdk) -> None:
        # create 34  bppstpads
        self.boostpads = [BoostPad(x, y, z, is_big) for x, y, z, is_big in BoostPad.BOOST_LOCATIONS]
        self.sdk = sdk
        pass


    def reset_boostpads(self):
        for pad in self.boostpads:
            pad.reset()


    def find_boostpad_by_location(self, x, y, z, tolerance=100.0):
        target_location = Vector(x, y, z)
        for pad in self.boostpads:
            if pad.location.distance_to(target_location) <= tolerance:
                return pad
        return None
    
    def find_boostpad_from_pickup(self, pickup: VehiclePickupBoost):
        x, y, z = pickup.get_location().get_xyz()
        return self.find_boostpad_by_location(x, y, z)
    


class FBox(Pointer):
    size = 0x0019

    def get_min(self):
        min_address = self.address
        return FVector(min_address, sdk=self.sdk)
    
    def get_max(self):
        max_address = self.address + 0x000C
        return FVector(max_address, sdk=self.sdk)
    
    def is_valid(self):
        return self.sdk.pm.read_uchar(self.address + 0x0018)
  

class Goal(UObject):
    size = 0x01C0

    def get_location(self):
        location_address = self.address + 0x0138
        return FVector(location_address, sdk=self.sdk)
    
    def get_direction(self):
        direction_address = self.address + 0x0144
        return FVector(direction_address, sdk=self.sdk)

    def get_right(self):
        right_address = self.address + 0x0150
        return FVector(right_address, sdk=self.sdk)

    def get_up(self):
        up_address = self.address + 0x015C
        return FVector(up_address, sdk=self.sdk)
    
    def get_rotation(self):
        rotation_address = self.address + 0x0168
        return FRotator(rotation_address, sdk=self.sdk)

    def get_team_num(self):
        return self.sdk.pm.read_uchar(self.address + 0x00DC)

    def get_world_box(self):
        box_address = self.address + 0x01A4
        return FBox(box_address, sdk=self.sdk)

    def get_width(self):
        box = self.get_world_box()
        min_x, min_y, min_z = box.get_min().get_xyz()
        max_x, max_y, max_z = box.get_max().get_xyz()
        return max_x - min_x

    def get_height(self):
        box = self.get_world_box()
        min_x, min_y, min_z = box.get_min().get_xyz()
        max_x, max_y, max_z = box.get_max().get_xyz()
        return max_y - min_y
 

class BoostPad():

    BOOST_LOCATIONS = (
        (0.0, -4240.0, 70.0, False),
        (-1792.0, -4184.0, 70.0, False),
        (1792.0, -4184.0, 70.0, False),
        (-3072.0, -4096.0, 73.0, True),
        (3072.0, -4096.0, 73.0, True),
        (- 940.0, -3308.0, 70.0, False),
        (940.0, -3308.0, 70.0, False),
        (0.0, -2816.0, 70.0, False),
        (-3584.0, -2484.0, 70.0, False),
        (3584.0, -2484.0, 70.0, False),
        (-1788.0, -2300.0, 70.0, False),
        (1788.0, -2300.0, 70.0, False),
        (-2048.0, -1036.0, 70.0, False),
        (0.0, -1024.0, 70.0, False),
        (2048.0, -1036.0, 70.0, False),
        (-3584.0, 0.0, 73.0, True),
        (-1024.0, 0.0, 70.0, False),
        (1024.0, 0.0, 70.0, False),
        (3584.0, 0.0, 73.0, True),
        (-2048.0, 1036.0, 70.0, False),
        (0.0, 1024.0, 70.0, False),
        (2048.0, 1036.0, 70.0, False),
        (-1788.0, 2300.0, 70.0, False),
        (1788.0, 2300.0, 70.0, False),
        (-3584.0, 2484.0, 70.0, False),
        (3584.0, 2484.0, 70.0, False),
        (0.0, 2816.0, 70.0, False),
        (- 940.0, 3310.0, 70.0, False),
        (940.0, 3308.0, 70.0, False),
        (-3072.0, 4096.0, 73.0, True),
        (3072.0, 4096.0, 73.0, True),
        (-1792.0, 4184.0, 70.0, False),
        (1792.0, 4184.0, 70.0, False),
        (0.0, 4240.0, 70.0, False),
    )


    def __init__(self, x, y, z, is_big = False) -> None:
        self.is_active = True
        self.is_big = is_big
        self.location = Vector(x, y, z)
        self.picked_up_time = None

    def reset(self):
        self.is_active = True
        self.is_big = False
        self.picked_up_time = None

class Vector():
    def __init__(self, x=0, y=0, z=0):
        self.x = x
        self.y = y
        self.z = z

    def distance_to(self, other):
        return ((self.x - other.x) ** 2 + (self.y - other.y) ** 2 + (self.z - other.z) ** 2) ** 0.5