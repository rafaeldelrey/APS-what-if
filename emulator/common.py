import os
import sys
import subprocess


def open_file(filename):
    """Open a file with the default application."""
    if sys.platform == "win32":
        os.startfile(filename)
    else:
        opener = "open" if sys.platform == "darwin" else "xdg-open"
        subprocess.call([opener, filename])
