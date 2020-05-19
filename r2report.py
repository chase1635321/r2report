#! /usr/bin/env python3
# Copyright (C) 2017 Chase Kanipe

"""
r2report
"""

from __future__ import print_function

import r2lang
import r2pipe
import os
from termcolor import colored

# Add command to access old mounting commands

r = r2pipe.open()


def r2report(_):
    """Build the plugin"""
    title = "Malware Report"
    installationtext = "This malware is a standalone executable. It might be dropped via a drive by download, manually installed on the computer, or act as a payload."
    behaviortext = "This malware waits until january 1, 2100 and then attempts a DDOS attack on malwareanalysisbook.com"
    persistencetext = "The malware sets itself up as a service named MalService."
    removaltext = "This malware can be detected using a mutext named HGL345 and the service Malservice. It can then be removed by uninstalling the service and rebooting."

    lines = []

    binary = r.cmdj("ij")["core"]["file"]

    def process(command):
        """Process commands here"""
        global lines

        if not command.startswith("R"): 
		return 0
        if command == "Ro":
            try:
                generateReport()
            except Exception as e:
                print(e)
        elif command == "Re":
            try:
                string_printer()
            except Exception as e:
                print(e)
        elif command == "rsa":
            try:
                string_identifier()
            except Exception as e:
                print(e)
        else:
            print("| R                  " + colored("print this help menu", "green"))
            print("| Re                 " + colored("generate report", "green"))
            print("| Rp                 " + colored("Print the report", "green"))
            print("| Rw                 " + colored("Write the report to an html file", "green"))
            # Command to iterate through all, strings, 

        return 1

    return {"name": "r2report",
            "licence": "GPLv3",
            "desc": "A plugin that generates reports from r2 projects",
            "call": process}


# Register the plugin
if not r2lang.plugin("core", r2report):
    print("An error occurred while registering r2report")

