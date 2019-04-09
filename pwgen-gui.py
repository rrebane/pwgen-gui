#!/usr/bin/env python

import argparse
import logging
import re
import sys
import traceback

import PySimpleGUI as sg

from about import ABOUT_TEXT
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

from scripts.solver import SolverError

VERSION_MAJOR = 0
VERSION_MINOR = 1
VERSION_PATCH = 0
VERSION_STR = '{}.{}.{}'.format(VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH)

MODULES = [
    pwgen_5dec,
    pwgen_asus,
    pwgen_dell,
    pwgen_fsi_5x4dec,
    pwgen_fsi_6x4dec,
    pwgen_fsi_hex,
    pwgen_hpmini,
    pwgen_insyde,
    pwgen_samsung,
    pwgen_sony_4x4,
    pwgen_sony_serial,
]

INPUT_TAG = 'Input'

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
        # Load the solvers
        solvers = []
        for module in MODULES:
            solvers.extend(module.solvers())

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

        info_header_layout = [[
            sg.Text('Vendor', size=(25, 1)),
            sg.Text('Info', size=(35, 1)),
            sg.Text('Examples', size=(30, 1)),
        ]]

        info_body_layout = []
        solvers.sort(key=lambda solver: solver.vendor)
        for solver in solvers:
            info_body_layout.append([
                sg.Text(solver.vendor, size=(25, 1)),
                sg.Text(solver.description, size=(35, 1)),
                sg.Text('\n'.join(solver.example), size=(30, len(solver.example))),
            ])

        info_header_column = sg.Column(info_header_layout)
        info_body_column = sg.Column(info_body_layout, scrollable=True,
                                     vertical_scroll_only=True)

        info_column = sg.Column([[info_header_column],
                                 [info_body_column]])

        window_layout = [
            [sg.Menu(menu)],
            [sg.Text('Input'),
             sg.InputText('', key=INPUT_TAG, do_not_clear=True),
             sg.Button('Run', bind_return_key=True)],
            [sg.Text('Output')],
            [sg.Output(size=(98, 20), pad=(20, 5))],
            [info_column],
        ]

        # Tried resizable=True, but since the inner components do not resize
        # properly, it is not very useful.
        window = sg.Window('Pwgen GUI', auto_size_text=True,
                           auto_size_buttons=True, grab_anywhere=False)
        window.Layout(window_layout)

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

                # Handle input
                if event == 'Run' and INPUT_TAG in values:
                    # Do nothing, if input is empty
                    if values[INPUT_TAG]:
                        solver_input = values[INPUT_TAG]
                        logger.info('Running solvers for input: %s',
                                    solver_input)
                        print('Running solvers for input: {}'.format(solver_input))
                        window.Refresh()

                        # Run solvers
                        found_solver = False
                        for solver in solvers:
                            if solver.is_valid_input(solver_input):
                                found_solver = True
                                info_str = solver.description
                                try:
                                    password = solver.solve(solver_input)
                                    logger.info('* %s: %s', info_str, password)
                                    print('* {}: {}'.format(info_str, password))
                                    window.Refresh()
                                except SolverError as e:
                                    logger.error('* %s: [ERROR] %s', info_str, e)
                                    print('* {}: [ERROR] {}'.format(info_str, e))
                                    window.Refresh()
                                except:
                                    formatted_lines = traceback.format_exc()
                                    logger.error('Error while running solver.'
                                                 ' Check if the input has the correct format.')
                                    logger.error(formatted_lines)
                                    print('Error while running solver.'
                                          ' Check if the input has the correct format.')
                                    print(formatted_lines)
                                    window.Refresh()

                        if not found_solver:
                            logger.info('No solvers found for input: %s',
                                        solver_input)
                            print('No solvers found for input: {}'.format(solver_input))
                            window.Refresh()

        finally:
            window.Close()
    except:
        formatted_lines = traceback.format_exc()
        logger.error(formatted_lines)

if __name__ == '__main__':
    main()
