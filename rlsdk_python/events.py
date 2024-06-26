from .game_objects import Car, UFunction, FName, BoostPad, PlayerController
from typing import Any
from .event_handling import EventData



class EventBoostPadChanged(EventData):
    def __init__(self, boostpad: BoostPad):
        self.boostpad = boostpad

class EventFunctionHooked(EventData):
    def __init__(self, function: UFunction, args: list[Any]):
        self.function = function
        self.args = args

class EventPlayerTick(EventData):
    def __init__(self, deltatime: float):
        self.deltatime = deltatime


class EventRoundActiveStateChanged(EventData):
    def __init__(self, is_active: bool):
        self.is_active = is_active

class EventResetPickups(EventData):
    def __init__(self):
        pass

class EventGameEventStarted(EventData):
    def __init__(self):
        pass

class EventGameEventDestroyed(EventData):
    def __init__(self):
        pass
    
class EventChatMessage(EventData):
    def __init__(self, player_controller: PlayerController, message: str, channel: int, preset: bool):
        self.channel = channel
        self.player_controller = player_controller
        self.message = message
        
        
class EventKeyPressed(EventData):

    types = {
        0: "pressed",
        1: "released",
        2: "repeat",
        3: "doubleclick",
        4: "axis"
    }

    def __init__(self, bytes, key):

        self.is_gamepad = bytes[20] & 0x01
        self.controller_id = int.from_bytes(bytes[0:4], byteorder='little')
        self.return_value = bytes[24] & 0x01
        self.key = key 
        self.type = self.types[int.from_bytes(bytes[12:13], byteorder='little')]


class EventTypes:
    ON_HOOKED_FUNCTION_CALLED = "on_hooked_function_called"
    ON_PLAYER_TICK = "on_player_tick"
    ON_ROUND_ACTIVE_STATE_CHANGED = "on_round_active_state_changed" 
    ON_RESET_PICKUPS = "on_reset_pickups"
    ON_GAME_EVENT_STARTED = "on_game_event_started"
    ON_KEY_PRESSED = "on_key_pressed"
    ON_BOOSTPAD_CHANGED = "on_boostpad_changed"
    ON_GAME_EVENT_DESTROYED = "on_game_event_destroyed"
    ON_CHAT_MESSAGE = "on_chat_message"
