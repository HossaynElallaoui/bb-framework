"""bb — opencode-native bug-bounty / HTB automation CLI.

The deterministic brain lives in lib/state.py; everything in this package is
either a thin wrapper around it, a deterministic port of the upstream
agentic-bug-hunter tooling, or presentation (rich/HTML). No module here calls
a model.
"""

__version__ = "1.0.0"
