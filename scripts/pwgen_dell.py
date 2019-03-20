#!/usr/bin/env python

def info():
    return '\n'.join([
        "Master Password Generator for Dell laptops",
        "Copyright (C) 2019 Reimo Rebane <rebanerebane@gmail.com>",
        "Original program in C by 2007-2010 hpgl",
        "",
        "Short service tag should be right padded with '*' up to length 7 chars.",
        "HDD serial number is right 11 chars from real HDDSerNum left padded with '*'.",
        "Some BIOSes have left padded HDD serial number with spaces instead '*'.",
    ])

def run(in_str = None):
    if in_str is None:
        print(info())
        in_str = input("Please enter the system date: ")

    password = "TODO"

    print(("The master password is: " + password))

if __name__ == "__main__":
    run()
