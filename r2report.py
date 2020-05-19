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

r = r2pipe.open()

def r2report(_):
    """Build the plugin"""

    binary = r.cmdj("ij")["core"]["file"]
    lines = []

    def process(command):
        """Process commands here"""
        global lines

        if not command.startswith("R"): 
            return 0

        r.cmd("e scr.color = 0")

        if command == "Ri":
            try:
                os.system("cp template.md report.md")
                print("Initialized report.md")
            except Exception as e:
                print(e)
        elif command == "Re":
            try:
                os.system("vim report.md")
            except Exception as e:
                print(e)
        elif command == "Rp":
            try:
                os.system("cat report.md")
            except Exception as e:
                print(e)
        elif command == "Rw":
            try:
                writeReport()
            except Exception as e:
                print(e)
        elif command == "Ro":
            try:
                os.system("gnome-open report.html &")
            except Exception as e:
                print(e)
        else:
            print("| R                  " + colored("print this help menu", "green"))
            print("| Ri                 " + colored("initialize report with template specified in template.md", "green"))
            print("| Re                 " + colored("edit the report", "green"))
            print("| Rp                 " + colored("print the report", "green"))
            print("| Rw                 " + colored("prite the report to report.html", "green"))
            print("| Ro                 " + colored("open report.html in browser", "green"))

        r.cmd("e scr.color = 3")

        return 1

    def writeReport():
        global lines

        print("Writing report")

        lines = []
        data = ""
        with open("template.html") as f:
            data = f.read()

        addLine = True
        for line in data.split("\n"):
            if "<article>" in line:
                addLine = False
                lines.append("<article>")
                generateReport()
            if "</article>" in line:
                addLine = True
            if addLine:
                lines.append(line)

        with open("report.html", "w+") as f:
            f.write("\n".join(lines))

    def generateReport():
        global lines
        data = ""
        with open("report.md") as f:
            data = f.read()

        for line in data.split("\n"):
            if line.startswith("# "):
                lines.append("<h1>" + line[2:] + "</h1>")
            elif line.startswith("## "):
                lines.append("<h2>" + line[3:] + "</h2>")
            elif line.startswith("### "):
                lines.append("<h3>" + line[4:] + "</h3>")
            elif line.startswith("#### "):
                lines.append("<h4>" + line[5:] + "</h4>")
            elif line.startswith("!"):
                lines.append("<pre><code>" + getCode(line[1:]) + "</code></pre>")
            elif line.startswith("---"):
                lines.append("<hr>")
            elif "$appendix" in line:
                lines.append("<hr>")
                lines.append("<h2>Appendix</h2>")

                lines.append("<h3>File Information</h3>")
                addCollapsible("Show sections", "<pre>" + r.cmd("iS").replace("\n", "<br>") + "</pre>")
                addCollapsible("Show file info", "<pre>" + r.cmd("i").replace("\n", "<br>") + "</pre>")
                addCollapsible("Show hashes", "<pre>" + r.cmd("it").replace("\n", "<br>") + "</pre>")

                lines.append("<h3>Functions</h3>")
                addCollapsible("Show function offsets", "<pre>" + r.cmd("aflt").replace("\n", "<br>") + "</pre>")

                lines.append("<h3>Data references</h3>")
                addCollapsible("Show import list", "<pre>" + r.cmd("ii").replace("\n", "<br>") + "</pre>")
                addCollapsible("Show export list", "<pre>" + r.cmd("iE").replace("\n", "<br>") + "</pre>")
                addCollapsible("Show string list", "<pre>" + r.cmd("izz").replace("\n", "<br>") + "</pre>")
            else:
                lines.append("<p>" + line + "</p>")

    def getCode(command):
        data = r.cmd(command)
        output = ""
        for line in data.split("\n"):
            lastwascall = False
            if not " ;-- " in line and not " ; var " in line and not "// WARNING: [r2ghidra]" in line:
                for word in line.split(";")[0].split(" "):
                    if str(word).startswith("0x"):
                        output += "<span style=\"color: darkgreen;\">" + str(word) + "</span> "
                    elif lastwascall:
                        output += "<span style=\"color: green;\"><b>" + word + "</b></span> "
                        lastwascall = False
                    elif len(word) == 3 and not "-" in word:
                        output += "<span style=\"color: blue;\">" + str(word) + "</span> "
                    elif len(word.replace(",", "")) == 3 and not "-" in word:
                        output += "<span style=\"color: blue;\">" + str(word[:3]) + "</span>, "
                    elif "call" in word:
                        output += "<span style=\"color: green;\"><b>" + word + "</b></span> "
                        lastwascall = True
                    elif "str." in word:
                        output += "<span style=\"color: red;\">" + word + "</span> "
                    elif len(word) > 0 and word[0] == "[" and word[-1] == "]":
                        output += "[<span style=\"color: red;\">" + word[1:-1] + "</span>] "
                    else:
                        n = 2
                        pairs = [word[i:i+n] for i in range(0, len(word), n)]
                        for pair in pairs:
                            try:
                                temp = int(pair, 16)
                                if len(pair) != 2:
                                    pair += 2 # Throws error
                                output += "<span style=\"color: darkyellow;\">" + pair + "</span>"
                            except:
                                output += pair
                        output += " "
                output += "\n"

        return output

    def addCollapsible(title, text):
        global lines
        lines.append("""<button class="collapsible">""" + title + """</button><div class="content"><p>""" + text + """</p></div>""")


    return {"name": "r2report",
            "licence": "GPLv3",
            "desc": "A plugin that generates reports from r2 projects",
            "call": process}

# Register the plugin
if not r2lang.plugin("core", r2report):
    print("An error occurred while registering r2report")

