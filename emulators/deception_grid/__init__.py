# Deception Grid's own Conpot emulators. Deliberately outside site-packages:
# a `uv pip install --upgrade conpot` would delete anything placed in there,
# and take the decoy's behaviour with it. Reached via PYTHONPATH instead --
# conpot/core/databus.py resolves a template's `function = "a.b.C"` with
# __import__, so any importable module works.
