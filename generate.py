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

        if not command.startswith("r"):
            return 0
        if command == "rg":
            try:
                generateReport()
            except Exception as e:
                print(e)
        elif command == "rs":
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
            print("| r                  " + colored("print this help menu", "green"))
            print("| rg                 " + colored("generate report", "green"))
            print("| rs                 " + colored("print strings in report", "green"))
            print("| rsa                " + colored("iterate through strings, adding them to report", "green"))
            # Command to iterate through all, strings, 

        return 1

    def generateReport():
        global lines

        print("Running r2report")
        os.system("rm -r report")
        os.system("cp -r template report")

        #lines = []
        #raw = ""
        #with open("report/content.xml", "r") as f:
        #    raw = f.read()

        #for line in raw.split("><"):
        #    lines.append(line)

        #os.system("rm components/base.xml")
        #with open("components/base.xml", "w") as f2:
        #    f2.write(">\n<".join(lines))

        lines = []
        raw = ""
        with open("components/base.xml", "r") as f:
            raw2 = f.read()

        for line in raw2.split(">\n<"):
            if line[0] == "#":
                if "Important strings" in line:
                    addImportantStrings()
                if "Important imports" in line:
                    addImportantImports()
            else:
                lines.append(line)

        fileinfo = r.cmdj("ij")
        hashes = r.cmdj("itj")

        sbox = [("Malware Analysis Report", title),
                ("installationtext", installationtext),
                ("behaviortext", behaviortext),
                ("persistencetext", persistencetext),
                ("removaltext", removaltext),
                ("filenametext", fileinfo["core"]["file"]),
                ("filesizetext", str(fileinfo["core"]["size"]) + " bytes"),
                ("sha1text", str(hashes["sha1"])),
                ("md5text", str(hashes["md5"])),
                ("sha256text", str(hashes["sha256"])),
                ("architecturetext", str(hashes["sha256"])),
                ("compilertext", str(fileinfo["bin"]["compiler"])),
                ("staticallylinkedtext", str(fileinfo["bin"]["static"])),
                ("strippedtext", str(fileinfo["bin"]["stripped"])),
                ]


        for i in range(0, len(lines)):
            for a, b in sbox:
                if a in lines[i]:
                    lines[i] = lines[i].replace(a, b)
                    pass

        for line in lines:
            #print(line)
            pass


        # =============== Write to file ===============

        raw = "><".join(lines)

        os.system("rm report/content.xml")
        with open("report/content.xml", "w") as f:
            f.write(raw)

        #return 1

        # =============== Table creation ===============

    def addImportantStrings():
        print("Adding important strings")

        comments = r.cmdj("CCj")
        for comment in comments:
            if "report (string): " in comment["name"]:
                addImportantString(hex(comment["offset"]), r.cmd("ps @ " + hex(comment["offset"])), comment["name"].split(": ")[1])


    def addImportantString(offset, string, description):
        global lines

        row = []
        with open("components/importantstrings.xml", "r") as f:
            row = f.read()[1:].split(">\n<")

        for i in range(0, len(row)):
            if "addresstext" in row[i]:
                row[i] = row[i].replace("addresstext", offset)
            if "stringtext" in row[i]:
                row[i] = row[i].replace("stringtext", string)
            if "descriptiontext" in row[i]:
                row[i] = row[i].replace("descriptiontext", description)
            lines.append(row[i])

    def addImportantImports():
        print("Adding important imports")

        comments = r.cmdj("CCj")
        for comment in comments:
            if "report (import): " in comment["name"]:
                for i in r.cmdj("iij"):
                    if i["plt"] == comment["offset"]:
                        xrefstext = r.cmd("axt @ " + hex(i["plt"])).split("\n")
                        xrefs = ""

                        for xref in xrefstext:
                            xrefs += xref.split(" ")[0]

                        addImportantImport(hex(comment["offset"]), i["name"], xrefs)

    def addImportantImport(offset, string, description):
        global lines

        row = []
        with open("components/importantimports.xml", "r") as f:
            row = f.read()[1:].split(">\n<")

        for i in range(0, len(row)):
            if "addresstext" in row[i]:
                row[i] = row[i].replace("addresstext", offset)
            if "importtext" in row[i]:
                row[i] = row[i].replace("importtext", string)
            if "xreftext" in row[i]:
                row[i] = row[i].replace("xreftext", description)
            lines.append(row[i])

    def string_printer():
        comments = r.cmdj("CCj")

        for comment in comments:
            if "report (string)" in comment["name"]:
                print(hex(comment["offset"]) + "\t" + r.cmd("ps @ " + hex(comment["offset"])).replace("\n", ""))

    def string_identifier():
        strings_json = r.cmdj("izj")

        i = 0
        j = len(strings_json)

        while i < j:
            os.system("clear")

            for k in range(i, i+20):
                try:
                    print(str(k) + "\t" + strings_json[k]["string"])
                except:
                    break
                i += 1

            while True:
                print("Input string index: ", end="")
                index = input()
                if index == "":
                    print("Breaking loop")
                    break
                else:
                    r.cmd("s " + hex(strings_json[int(index)]["vaddr"]))
                    r.cmd("CCu report (string): string")

    return {"name": "r2report",
            "licence": "GPLv3",
            "desc": "A plugin that generates reports from r2 projects",
            "call": process}


# Register the plugin
if not r2lang.plugin("core", r2report):
    print("An error occurred while registering r2report")

