# RLSDK Python

This is reverse engineered python SDK package aiming to read data from RocketLeague.exe.

## How does it works 
This SDK uses [PyMem](https://pypi.org/project/Pymem/) to read game memory and [frida](https://frida.re/docs/home/) to hook game functions. 

## Installation

```bash
pip install rlsdk_python
```
Or
```bash
poetry add rlsdk_python
```

## Usage

```python
from rlsdk_python import RLSDK, EventTypes
import sys

rlsdk = RLSDK(hook_player_tick=True)


def on_tick(event):
    game_event = rlsdk.get_game_event()

    if game_event:
        cars = game_event.get_cars()
        
        for car in cars:
            pri = car.get_pri()
            player_name = pri.get_player_name()

            # Display car position

            x,y,z = car.get_location().get_xyz()

            print(f"{player_name} is at {x},{y},{z}")

rlsdk.event.subscribe(EventTypes.ON_PLAYER_TICK, on_tick)

sys.stdin.read()

```

## Events

You can attach a callback function to an event like this:

```python
from rlsdk_python import RLSDK, EventTypes
sdk = RLSDK()
sdk.event.subscribe(EventTypes.ON_KEY_PRESSED, on_key_pressed)

def on_key_pressed(event):
    print("Key pressed:", event.key)

```

More examples and documentation will be added if users ask for it.




## Project using RLSDK Python

- [RLMarlbot](https://github.com/MarlBurroW/RLMarlbot) - Nexto bot based on my python SDK

## Help needed
I need a way to find GObjects and GNames base offsets, because this offsets changes frequently (on each uptates) and are differents for Epic and Steam


