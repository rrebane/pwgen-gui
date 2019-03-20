#!/usr/bin/env python

import argparse
import logging
import re
import sys
import traceback

import PySimpleGUI as sg

from about import ABOUT_TEXT, ABOUT_IMAGE_BASE64
from license import LICENSE

from scripts import pwgen_5dec
from scripts import pwgen_asus
from scripts import pwgen_dell
from scripts import pwgen_fsi_5x4dec
from scripts import pwgen_fsi_6x4dec
from scripts import pwgen_fsi_hex
from scripts import pwgen_hpmini
from scripts import pwgen_insyde
from scripts import pwgen_samsung
from scripts import pwgen_sony_4x4
from scripts import pwgen_sony_serial

VERSION_MAJOR = 0
VERSION_MINOR = 1
VERSION_PATCH = 0
VERSION_STR = '{}.{}.{}'.format(VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH)

MODULES = [
    {
        'vendor': 'Asus',
        'encoding': 'Machine Date',
        'example': '01-01-2011',
        'validation': re.compile(r'\s*\d{2}-\d{2}-\d{4}\s*'),
        'module': pwgen_asus,
    },
    {
        'vendor': 'Compaq',
        'encoding': '5 decimal digits',
        'example': '12345',
        'validation': re.compile(r'\s*\d{5}\s*'),
        'module': pwgen_5dec,
    },
    {
        'vendor': 'Dell',
        'encoding': 'serial number',
        'example': '1234567-595B',
        'validation': re.compile(r'\s*\w{7}-\w{4}\s*'),
        'module': pwgen_dell,
    },
    {
        'vendor': 'Fujitsu-Siemens',
        'encoding': '5 decimal digits',
        'example': '12345',
        'validation': re.compile(r'\s*\d{5}\s*'),
        'module': pwgen_5dec,
    },
    {
        'vendor': 'Fujitsu-Siemens',
        'encoding': '8 hexadecimal digits',
        'example': 'DEADBEEF',
        'validation': re.compile(r'\s*[0-9a-fA-F]{8}\s*'),
        'module': pwgen_fsi_hex,
    },
    {
        'vendor': 'Fujitsu-Siemens',
        'encoding': '5x4 hexadecimal digits',
        'example': 'AAAA-BBBB-CCCC-DEAD-BEEF',
        'validation': re.compile(r'\s*[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}\s*'),
        'module': pwgen_fsi_hex,
    },
    {
        'vendor': 'Fujitsu-Siemens',
        'encoding': '5x4 decimal digits',
        'example': '1234-4321-1234-4321-1234',
        'validation': re.compile(r'\s*\d{4}-\d{4}-\d{4}-\d{4}-\d{4}\s*'),
        'module': pwgen_fsi_5x4dec,
    },
    {
        'vendor': 'Fujitsu-Siemens',
        'encoding': '6x4 decimal digits',
        'example': '8F16-1234-4321-1234-4321-1234',
        'validation': re.compile(r'\s*[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}\s*'),
        'module': pwgen_fsi_6x4dec,
    },
    {
        'vendor': 'Hewlett-Packard',
        'encoding': '5 decimal digits',
        'example': '12345',
        'validation': re.compile(r'\s*\d{5}\s*'),
        'module': pwgen_5dec,
    },
    {
        'vendor': 'Hewlett-Packard/Compaq Netbooks',
        'encoding': '10 characters',
        'example': 'CNU1234ABC',
        'validation': re.compile(r'\s*\w{10}\s*'),
        'module': pwgen_hpmini,
    },
    {
        'vendor': 'Insyde H20 (generic)',
        'encoding': '8 decimal digits',
        'example': '03133610',
        'validation': re.compile(r'\s*\d{8}\s*'),
        'module': pwgen_insyde,
    },
    {
        'vendor': 'Phoenix (generic)',
        'encoding': '5 decimal digits',
        'example': '12345',
        'validation': re.compile(r'\s*\d{5}\s*'),
        'module': pwgen_5dec,
    },
    { # TODO this is currently broken
        'vendor': 'Sony',
        'encoding': '4x4 hexadecimal digits',
        'example': '1234-1234-1234-1234',
        'validation': re.compile(r'\s*\d{4}-\d{4}-\d{4}-\d{4}\s*'),
        'module': pwgen_sony_4x4,
    },
    {
        'vendor': 'Sony',
        'encoding': '7 digit serial number',
        'example': '1234567',
        'validation': re.compile(r'\s*\d{7}\s*'),
        'module': pwgen_sony_serial,
    },
    { # TODO this is currently broken
        'vendor': 'Samsung',
        'encoding': '12 hexadecimal digits',
        'example': '07088120410C0000',
        'validation': re.compile(r'\s*[0-9a-fA-F]{12}\s*'),
        'module': pwgen_samsung,
    },
]

MODULE_NAMES = ['{}, {} ({})'.format(m['vendor'], m['encoding'], m['example']) for m in MODULES]

MODULE_TAG = 'Module'
INPUT_TAG = 'Input'

def selected_module(name):
    try:
        idx = MODULE_NAMES.index(name)

        if idx < 0 and idx >= len(MODULES):
            return None

        return MODULES[idx]
    except ValueError:
        return None

def main():
    # Parse program arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('--logfile', help='File for log info')
    parser.add_argument('--loglevel', help='Log level (CRITICAL, ERROR, WARNING, INFO, DEBUG)')
    parser.add_argument('--version', help='Print version and exit',
                        action='store_true')
    args = parser.parse_args()

    # Print version
    if args.version:
        print(VERSION_STR)
        sys.exit(0)

    # Set up logging
    logger = logging.getLogger(__name__)

    try:
        if args.loglevel:
            if args.loglevel == 'CRITICAL':
                logger.setLevel(level=logging.CRITICAL)
            elif args.loglevel == 'ERROR':
                logger.setLevel(level=logging.ERROR)
            elif args.loglevel == 'WARNING':
                logger.setLevel(level=logging.WARNING)
            elif args.loglevel == 'INFO':
                logger.setLevel(level=logging.INFO)
            elif args.loglevel == 'DEBUG':
                logger.setLevel(level=logging.DEBUG)
            else:
                print('Invalid log level parameter: {}'.format(args.loglevel), file=sys.stderr)
                parser.print_help()
                sys.exit(1)
        else:
            logger.setLevel(level=logging.INFO)

        formatter = logging.Formatter(fmt='%(asctime)s %(levelname)-8s %(message)s',
                                      datefmt='%Y-%m-%d %H:%M:%S')

        stdout_handler = logging.StreamHandler(stream=sys.stdout)
        stdout_handler.setFormatter(formatter)
        logger.addHandler(stdout_handler)

        if args.logfile:
            file_handler = logging.FileHandler(args.logfile)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
    except:
        print('Error while setting up logging:', file=sys.stderr)
        formatted_lines = traceback.format_exc()
        print(formatted_lines, file=sys.stderr)
        parser.print_help()
        sys.exit(1)

    try:
        # Format the about page information
        about_body = '\n'.join([
            'Pwgen GUI {}'.format(VERSION_STR),
            '',
            ABOUT_TEXT,
        ])

        # Set up GUI components
        menu = [
            ['&File', 'E&xit'],
            ['&Help', ['&License', '&About']],
        ]

        info_text = sg.Text(MODULES[1]['module'].info())

        layout = [
            [sg.Menu(menu)],
            [sg.Text('Modules'),
             sg.InputCombo(MODULE_NAMES,
                           enable_events=True,
                           key=MODULE_TAG,
                           readonly=True)],
            [sg.Frame('Module Info', [[info_text]], size=(80, 100))],
            [sg.Text('Input'),
             sg.InputText('', key=INPUT_TAG, do_not_clear=True)],
            [sg.Text('Output')],
            [sg.Output(size=(80, 20))],
            [sg.Button('Run')],
        ]

        window = sg.Window('Pwgen GUI', default_element_size=(40, 1), grab_anywhere=False)
        window.Layout(layout)

        # Main loop
        try:
            while True:
                event, values = window.Read()
                logger.info('event=%s, values=%s', event, values)

                # Program is closing
                if not event:
                    break

                # Handle menu events
                if event == 'Exit':
                    break
                elif event == 'License':
                    sg.PopupScrolled('License', '', LICENSE)
                elif event == 'About':
                    # TODO about contents
                    sg.Popup('About', about_body)

                # Show module info
                if event == MODULE_TAG and MODULE_TAG in values:
                    module = selected_module(values[MODULE_TAG])
                    if module:
                        info_text.Update(value=module['module'].info())

                # Run module
                if event == 'Run' and INPUT_TAG in values and MODULE_TAG in values:
                    module = selected_module(values[MODULE_TAG])

                    # Do nothing, if input is empty
                    if module and values[INPUT_TAG]:
                        module_input = values[INPUT_TAG]
                        logger.info('Running module with input: \'%s\'', module_input)
                        print('Running module with input: \'{}\''.format(module_input))
                        window.Refresh()

                        # Check if input matches the validation regex
                        if module['validation'].match(module_input):
                            try:
                                module['module'].run(values[INPUT_TAG])
                            except:
                                formatted_lines = traceback.format_exc()
                                logger.error('Error while running module.'
                                             ' Check if the input has the correct format.')
                                logger.error(formatted_lines)
                                print('Error while running module.'
                                      ' Check if the input has the correct format.')
                                print(formatted_lines)
                        else:
                            logger.error('Invalid input: \'%s\'', module_input)
                            print('Invalid input: \'{}\''.format(module_input))
                            window.Refresh()
        finally:
            window.Close()
    except:
        formatted_lines = traceback.format_exc()
        logger.error(formatted_lines)

if __name__ == '__main__':
    main()
