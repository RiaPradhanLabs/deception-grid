"""
plant.py -- register animation for the Deception Grid OT decoy.

WHY THIS FILE EXISTS AT ALL
---------------------------
Conpot's shipped plc_modbus template gives all four Modbus blocks a static
value: `value = "[0 for b in range(0,8)]"`. conpot/core/databus.py evaluates a
`value` expression ONCE, at initialisation, and stores the result -- so every
register on an unmodified Conpot reads zero for the life of the process. A
controller whose values never change is not controlling anything.

The tempting one-line fix does not work either. databus.py imports `random` at
module level with the comment "this is needed because we use it in template
value expressions", so `value = "[random.randint(0,100) for b in range(0,8)]"`
is legal -- and still evaluated once. The registers come out non-zero and then
never move again. That looks fixed and is not.

Animation is only possible through `function = "..."`, because databus.get_value
checks the stored object for a get_value attribute and CALLS IT on every lookup.

Conpot 1.0.0 ships two candidate classes in conpot/emulators/misc/random.py,
and neither is usable here:

  Random8BitRegisters  returns [0|1] x 8. Right shape for the two bit blocks,
                       wrong behaviour -- see "TIME, NOT CALL COUNT" below.
  Random16bitRegister  returns a list of ONE value, in the range 0 to 1. Our
                       register blocks are eight 16-bit words, and a 16-bit
                       register holds 0-65535. Wrong length and a meaningless
                       range; it looks like a bug in Conpot rather than a
                       design choice.

The other emulators are worse than unusable -- conpot.emulators.misc.sysinfo
reports the HOST's real CpuLoad, TotalRam, BytesSent and LocalIP. They exist
for the SNMP template, where a network device is meant to report its own
interfaces. Wiring any of them to a Modbus register would publish this VM's
private address and traffic counters to anyone who reads holding registers.

TIME, NOT CALL COUNT
--------------------
Every value here is a function of time.time(), never of how many times it has
been asked. get_value() runs on each read, so a freshly-random value would mean
two reads a second apart disagreeing completely -- no instrument behaves that
way, and a scanner that polls twice would see a plant where all eight digital
outputs flipped in three seconds. Deriving from wall-clock time means reads
close together agree and reads minutes apart differ, which is what a real
controller does. A small noise term is added to the analogue values only,
because a real ADC reading the same sensor twice genuinely does differ slightly.

The bit blocks use periods of 15 to 90 minutes, so outputs hold for minutes at
a time rather than chattering.

INTERNAL CONSISTENCY
--------------------
The blocks are not independent. Flow, motor speed and pump current collapse to
near-zero when the coils say no pump is running, and the flow switch in the
discrete inputs follows the pump commands in the coils. A decoy whose pumps
read off while flow reads 90 L/min is a worse tell than one reading all zeros,
because it is a contradiction rather than an absence.

THE SCENARIO
------------
A small heating and water circuit: two pumps (one duty, one standby), a mixing
valve, a buffer tank. Ordinary duty for a WAGO 750-8202, and consistent with
the vendor identity already served in [modbus.device_info].

Values are scaled integers, the usual Modbus convention, since a register holds
no decimal point:

  x10   temperatures (C), flow (L/min), tank level (%)
  x100  pressure (bar), current (A)
  x1    speed (rpm), counters, setpoint words

WIRED UP IN template.toml AS
----------------------------
  memoryModbusSlave1BlockA = { function = "deception_grid.plant.PlantCoils" }
  memoryModbusSlave1BlockB = { function = "deception_grid.plant.PlantDiscreteInputs" }
  memoryModbusSlave1BlockC = { function = "deception_grid.plant.PlantInputRegisters" }
  memoryModbusSlave1BlockD = { function = "deception_grid.plant.PlantHoldingRegisters" }

and needs PYTHONPATH=/home/conpot/emulators in the systemd unit, because this
module lives outside site-packages on purpose. Without it Conpot fails at
startup with ModuleNotFoundError -- loudly, which is the preferable failure.
"""

import math
import random
import time

# Commissioning date: 2024-03-11 00:00:00 UTC. The counters below run from here
# rather than from process start, so pump run-hours reads about 13,850 and the
# cycle counter has wrapped twice, instead of both starting at 0. A controller
# installed this morning is not what this is pretending to be. Both are kept
# inside 16 bits by the modulo; run-hours passes 65535 in 2038, which is a
# problem for a honeypot that is scheduled for teardown in December 2026.
EPOCH = 1710115200

MAX16 = 65535


def _clamp(value):
    """Modbus registers are unsigned 16-bit. Nothing leaves this file outside
    0-65535, so a change to a range below cannot produce a malformed reply."""
    if value < 0:
        return 0
    if value > MAX16:
        return MAX16
    return int(value)


def _wave(period_s, phase):
    """A smooth 0.0-1.0 value with the given period. Same instant in, same
    value out -- which is the whole point, see TIME, NOT CALL COUNT above."""
    return 0.5 + 0.5 * math.sin(2.0 * math.pi * ((time.time() / period_s) + phase))


def _span(low, high, period_s, phase, noise=0):
    """An integer drifting smoothly between low and high, plus sensor noise."""
    value = low + (high - low) * _wave(period_s, phase)
    if noise:
        value += random.uniform(-noise, noise)
    return _clamp(round(value))


def _coil_states():
    """The eight digital outputs. A module-level function rather than a method
    so that PlantDiscreteInputs can read the same states in the same instant
    and agree with them; two instances sharing mutable state would not."""
    pump1 = 1 if _wave(2400, 0.00) > 0.35 else 0   # duty pump, 40 min period
    pump2 = 1 if _wave(5400, 0.31) > 0.72 else 0   # standby, cuts in rarely
    valve = 1 if _wave(900, 0.57) > 0.50 else 0    # mixing valve, 15 min
    heat = 1 if _wave(1800, 0.13) > 0.45 else 0    # heater enable, 30 min
    #       0      1      2      3     4  5  6  7   -- 4 is the alarm horn,
    #                                                  5-7 are spare, as on a
    #                                                  real partly-used module
    return [pump1, pump2, valve, heat, 0, 0, 0, 0]


def _input_states():
    """The eight digital inputs. Feedback follows the commands: on real plant
    the contactor auxiliary echoes the output that closed it."""
    coils = _coil_states()
    flow_switch = 1 if (coils[0] or coils[1]) else 0
    thermostat = 1 if _wave(1800, 0.13) > 0.45 else 0
    return [
        coils[0],     # pump 1 running feedback
        coils[1],     # pump 2 running feedback
        coils[2],     # valve open limit switch
        flow_switch,  # flow proved
        thermostat,   # thermostat calling for heat
        1,            # cabinet door closed
        1,            # emergency stop healthy
        0,            # spare
    ]


class PlantCoils:
    """COILS, 8 bits -- what the controller is driving."""

    def get_value(self):
        return _coil_states()


class PlantDiscreteInputs:
    """DISCRETE_INPUTS, 8 bits -- what the field is telling it."""

    def get_value(self):
        return _input_states()


class PlantInputRegisters:
    """ANALOG_INPUTS, 8 x 16-bit -- measurements. Read-only on real plant."""

    def get_value(self):
        coils = _coil_states()
        running = coils[0] or coils[1]

        if running:
            flow = _span(620, 1150, 420, 0.00, noise=7)    # 62.0-115.0 L/min
            speed = _span(1180, 1465, 420, 0.00, noise=4)  # rpm
            amps = _span(520, 880, 420, 0.05, noise=5)     # 5.20-8.80 A
            press = _span(198, 252, 660, 0.22, noise=2)    # 1.98-2.52 bar
        else:
            # Standing losses only. Not exactly zero: a stopped pump still
            # shows a little thermosiphon flow and residual static pressure,
            # and a flow transmitter reading a clean 0 is itself unusual.
            flow = _span(0, 14, 300, 0.40, noise=3)
            speed = 0
            amps = _span(0, 6, 300, 0.40, noise=2)
            press = _span(150, 178, 900, 0.22, noise=2)

        return [
            flow,                                        # 0 flow L/min x10
            _span(556, 712, 1500, 0.11, noise=3),        # 1 supply C x10
            _span(382, 476, 1500, 0.19, noise=3),        # 2 return C x10
            press,                                       # 3 pressure bar x100
            _span(312, 842, 7200, 0.63, noise=4),        # 4 tank level % x10
            amps,                                        # 5 pump 1 current x100
            _span(128, 214, 43200, 0.50, noise=2),       # 6 ambient C x10
            speed,                                       # 7 motor speed rpm
        ]


class PlantHoldingRegisters:
    """HOLDING_REGISTERS, 8 x 16-bit -- setpoints and counters. Writable on
    real plant, which is exactly why a scanner reaching for these is the
    behaviour worth recording."""

    def get_value(self):
        elapsed = time.time() - EPOCH
        if elapsed < 0:
            elapsed = 0.0

        run_hours = int((elapsed / 3600.0) * 0.62) % 65536  # 62% duty
        cycles = int(elapsed / 480.0) % 65536               # a start every 8 min

        # Night setback. A fixed setpoint around the clock is a tell of its
        # own; every building controller drops at night. UTC rather than local
        # time, because everything in this project is UTC and a decoy whose
        # clock disagrees with its own logs is harder to explain than one whose
        # setback runs an hour off local.
        hour = time.gmtime().tm_hour
        supply_setpoint = 610 if (hour < 5 or hour >= 22) else 650

        return [
            supply_setpoint,  # 0 supply temperature setpoint C x10
            220,              # 1 pressure setpoint bar x100
            250,              # 2 tank level low alarm % x10
            900,              # 3 tank level high alarm % x10
            run_hours,        # 4 pump 1 run hours
            cycles,           # 5 pump start counter
            1,                # 6 control mode: 1 = auto, 0 = manual
            0,                # 7 fault word, no active faults
        ]
