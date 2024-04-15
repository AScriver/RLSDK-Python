from .game_objects import Car, UFunction
from typing import Any
from .event_handling import EventData


class EventBoostPadChanged(EventData):
    def __init__(self, car: Car):
        self.car = Car

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
    

class EventTypes:
    ON_HOOKED_FUNCTION = "on_hooked_function"
    ON_PLAYER_TICK = "on_player_tick"
    ON_ROUND_ACTIVE_STATE_CHANGED = "on_round_active_state_changed" 
    ON_RESET_PICKUPS = "on_reset_pickups"
    ON_GAME_EVENT_STARTED = "on_game_event_started"
    

