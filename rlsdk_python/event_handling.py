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

