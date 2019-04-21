# pwgen-gui

A thin wrapper around some BIOS password generation scripts

## Requirements

* Python 3.x
* Virtualenv/pip

## Setup

```
virtualenv pwgen-gui-virtualenv
source pwgen-gui-virtualenv/bin/activate
pip install pyinstaller pysimplegui
```

## Build

### Linux

```
pyinstaller --onefile pwgen-gui.py
```

### Windows

```
pyinstaller --windowed --onefile pwgen-gui.py
```

### OS X

```
# Install a Python version with the built-in Tcl/Tk
pyinstaller --windowed --add-binary='/System/Library/Frameworks/Tk.framework/Tk':'tk' --add-binary='/System/Library/Frameworks/Tcl.framework/Tcl':'Tcl' --onefile pwgen-gui.py
```
