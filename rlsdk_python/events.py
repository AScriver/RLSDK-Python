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
        
class EventTypes:
    ON_HOOKED_FUNCTION = "on_hooked_function"

    