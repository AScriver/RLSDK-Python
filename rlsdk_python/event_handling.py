from typing import Callable, Dict, TypeVar, Generic


T = TypeVar('T')

class EventData:
    """Classe de base pour les données d'événement."""
    pass

# Une classe générique où T est une sous-classe de EventData
class Event(Generic[T]):
    def __init__(self):
        self.subscribers: Dict[str, Callable[[T], None]] = {}

    def subscribe(self, event_type: str, callback: Callable[[T], None]) -> None:
        if event_type not in self.subscribers:
            self.subscribers[event_type] = []
        self.subscribers[event_type].append(callback)

    def fire(self, event_type: str, data: T) -> None:
        if not isinstance(data, EventData):
            raise ValueError("data must be an instance of EventData or its subclasses")
        for callback in self.subscribers.get(event_type, []):
            callback(data)

    def subscribe_once(self, event_type: str, callback: Callable[[T], None]) -> None:
        def wrapper(data: T):
            callback(data)
            self.unsubscribe(event_type, wrapper)
        self.subscribe(event_type, wrapper)

    def unsubscribe(self, event_type: str, callback: Callable[[T], None]) -> None:
        self.subscribers[event_type].remove(callback)
        
    def clear(self, event_type: str) -> None:
        self.subscribers[event_type].clear()

    def clear_all(self) -> None:
        self.subscribers.clear()

    # subcribe_once_block block the program until the event is fired
    def subscribe_once_block(self, event_type: str, callback: Callable[[T], None]) -> None:
        def wrapper(data: T):
            callback(data)
            self.unsubscribe(event_type, wrapper)
        self.subscribe(event_type, wrapper)
        while self.subscribers[event_type]:
            pass
        
