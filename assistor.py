#!/usr/bin/python3

import r2pipe
import os
import base64
from termcolor import colored

# Build function manual analyzer that traverses up the function call tree, picking the function closest to the bottom that has the highest percent renamed functions or library calls
# Add radare2 command to recursivley rename functions to ignore
# Replace pdfs with pdf~call
# Fix function iterate counter
# Make import marker work like string marker
# Traverse back over strings and import cross references to comment on their purpose
# Skip over leaf functions
# If function contains one call, rename call_that function and skip it
# Skip functions that call only no-name ones until the end
# Can add sections to analysis using comments Like "analysis: This block of of code does things; !pd 5 @ here; here is more information"
# Rename tiny functions to tiny1-n
# Rename functions that are tiny but call something to call-function
# Save project at the end
# Rename leaf functions containing rep st... to say _StringManipulation

os.system("clear")

r = r2pipe.open()

r.cmd("e prj.simple = true")

projectname = ""
imports = []
strings = []

def main():
    initialize()
    print_info()
    import_identifier()
    string_identifier()
    function_renamer()
    initialize_notes()
    function_iterate()

def function_iterate():
    i = 1
    temp = r.cmdj("aflj")
    funcs = []
    allfuncs = []

    for f in temp:
        if not "_" in f["name"]:
            allfuncs.append(f)
            
    for f in allfuncs:
        r.cmd("s " + hex(f["offset"]))
        if len(r.cmd("pdf~call")) - len(r.cmd("pdf~imp")) < len(r.cmd("pdf~imp")):
            if not user_rename_function(f, allfuncs, i):
                funcs.append(f)
        else:
            funcs.append(f)
        i += 1

    i = 0
    for f in funcs:
        r.cmd("s " + hex(f["offset"]))
        user_rename_function(f, allfuncs, i)
        i += 1

def user_rename_function(f, funcs, i):
    os.system("clear")
    print(str(i) + "/" + str(len(funcs)) + " ", end="")
    print(f["signature"])
    data = r.cmd("pdf~call")
    for line in data.split("\n"):
        try:
            if not "CALL" in line:
                print("0x" + line.split(";")[0].split("0x")[1])
        except:
            print(line)
    cmd = input()
    if not cmd == "":
        r.cmd("afn " + cmd + "[" + f["name"].split("[")[1])
        return True
    return False

def initialize_notes():
    global projectname
    title = "# " + projectname + " Analysis" + "\n"
    title = base64.b64encode(title.encode())
    r.cmd("Pnj " + title.decode())
    r.cmd("Pn+" + "## Executive Summary")
    r.cmd("Pn+" + "### Installation")
    r.cmd("Pn+" + "How malware gets installed goes here")
    r.cmd("Pn+" + "")
    r.cmd("Pn+" + "### Behavior")
    r.cmd("Pn+" + "What the malware does goes here")
    r.cmd("Pn+" + "")
    r.cmd("Pn+" + "### Persistence")
    r.cmd("Pn+" + "How the malware persists on the system goes here")
    r.cmd("Pn+" + "")
    r.cmd("Pn+" + "### Removal")
    r.cmd("Pn+" + "How the malware can be uninstalled goes here")
    r.cmd("Pn+" + "")
    r.cmd("Pn+" + "## Analysis")
    r.cmd("Pn+" + "Add detailed analysis here. Add code with !radare2 command")
    r.cmd("Pn+" + "")
    print(r.cmd("Pn"))

def function_renamer():
    for f in r.cmdj("aflj"):
        name = f["name"].split("[")[0]
        r.cmd("s " + name)
        name += "["

        code = r.cmd("pdf")
        size = f["size"]

        xrefs = len(r.cmdj("axtj"))
        calls = len(r.cmd("pdf~call").split("\n")) - 1
        
        name += str(calls) + "," + str(xrefs) + ","

        if calls == 0:
            name = "_" + name
        if size < 20:
            name += "small" + ","
        if size > 300:
            name += "large" + ","

        name = name.strip(",")
        name += "]"
        
        if len(code.split("\n")) < 10:
            if not "call" in code:
                name = "_tiny"+str(f["offset"])
            if calls == 1:
                name = "_callsfunc" + str(f["offset"])
        if calls == 0 and "rep " in code:
            name = "_stringmanipulation" + str(f["offset"])


        r.cmd("afn " + name)

def string_identifier():
    global strings
    strings_json = r.cmdj("izj")

    i = 0
    j = len(strings_json)
    print(str(j))
    
    while i < j:
        os.system("clear")

        for k in range(i, i+20):
            try:
                print(str(k) + "\t" + strings_json[k]["string"])
            except:
                break

        while True:
            print("Input string index: ", end="")
            index = input()
            if index == "":
                break
            else:
                r.cmd("s " + hex(strings_json[int(index)]["vaddr"]))
                r.cmd("CCu report: string")
                xrefs_json = r.cmdj("axtj")
                xrefs = []

                for xref in xrefs_json:
                    try:
                        xrefs.append((xref["from"], xref["fcn_name"]))
                    except:
                        xrefs.append((xref["from"], hex(xref["from"])))

                strings.append((hex(strings_json[int(index)]["vaddr"]), strings_json[int(index)]["string"], xrefs))
        i += 20

def import_identifier():
    global imports
    imports_json = r.cmdj("iij")
    print(r.cmd("ii"))
    
    val = "blabla"
    while val != "":
        print("Input relevant imports: ", end="")
        val = input()

        if val == "":
            continue

        found = False
        for i in imports_json:
            if i["name"].strip() == val.strip():
                found = True
                addr = hex(i["plt"])
        if found:
            imports.append((addr, val))
            r.cmd("s " + addr)
            r.cmd("CCu report: import")
        else:
            print(colored("Import name not found", "red"))


    
def print_info():
    print(colored("Malware info: ", "yellow"))
    print("   " + r.cmd("i~format").strip())
    print("   " + r.cmd("i~arch").strip())
    print("   " + r.cmd("i~bits").strip())
    print("   " + r.cmd("i~nx").strip())
    print("   " + r.cmd("i~os").strip())
    print("   " + r.cmd("i~static").strip())
    print("   " + r.cmd("i~stripped").strip())

def initialize():
    global projectname
    print("Enter project name: ", end = "") 
    projectname = input()

    if projectname == "":
        projectname = r.cmdj("ij")["core"]["file"]

    r.cmd("Pd " + projectname)

    print(colored("Analyzing file", "yellow"))
    r.cmd("aaa")

    print(colored("\nSaving project as " + projectname, "yellow"))
    r.cmd("Ps " + projectname)

main()
