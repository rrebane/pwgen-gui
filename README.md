# pwgen-gui

A thin wrapper around some BIOS password generation scripts

## Requirements

* Python 3.x
* Virtualenv/pip

## Setup

```
virtualenv pwgen-gui-virtualenv
source pwgen-gui-virtualenv
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
pyinstaller --windowed --onefile pwgen-gui.py
```
