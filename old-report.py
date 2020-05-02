#!/usr/bin/python3

import r2pipe
import os
import base64

r = r2pipe.open()

r.cmd("e prj.simple = true")

os.system("rm report.md")
os.system("clear")

f = open("report.md", "a")

projectname = r.cmd("Ps").strip()
print("Project name is: " + projectname)

def main():
    print("Creating report")
    addExecutiveSummary()
    addBasicInfo()
    addStrings()
    addImports()
    addFunctionInfo()
    addAnalysis()

def addAnalysis():
    r.cmd("e scr.color = 0")
    f.write(
"""

---

""")
    data = r.cmd("Pn")
    data2 = []
    atAnalysis = False
    for line in data.split("\n"):
        if "## Analysis" in line or atAnalysis:
            atAnalysis = True
            data2.append(line)

    text = ""
    for line in data2:
        if len(line) == 0:
            continue
        elif line[0] == "!":
            text += "```\n"
            output = r.cmd(line[1:])
            for line in output.split("\n"):
                text += line.split("; report")[0] + "\n"
            text += "```\n"
        else:
            text += line + "\n"
    f.write(text)
    r.cmd("e scr.color = 3")




def addImports():
    f.write(
"""

---

### Imports

| Address  | Import | XRefs |
|---|---|---|
""")
    for s in r.cmdj("iij"):
        name = s["name"]
        addr = hex(s["plt"])
        comment = r.cmd("CC. @ " + addr)
        xrefs = ""
        for xref in r.cmdj("axtj " + addr):
            try:
                if not xref["fcn_name"] in xrefs:
                    xrefs += xref["fcn_name"] + ", "
            except:
                print("Failed")
        xrefs = xrefs[:-2]

        if "report" in comment:
            f.write("| " + addr + " | " + name + " | " + xrefs + " |\n")

def addStrings():
    f.write(
"""

---

### Strings

| Address  | String  | XRefs |
|---|---|---|
""")
    for s in r.cmdj("izj"):
        r.cmd("s " + hex(s["vaddr"]))
        comment = r.cmd("CC.")
        if not "report" in comment:
            continue

        if s["size"] > 8:
            string = s["string"]
            addr = hex(s["vaddr"])
            xrefs = ""
            for xref in r.cmdj("axtj " + addr):
                #print(r.cmd("axtj~{}"))
                try:
                    if not xref["fcn_name"] in xrefs:
                        xrefs += xref["fcn_name"] + ", "
                except:
                    print("Failed")
            xrefs = xrefs[:-2]

            f.write("| " + addr + " | " + string + " | " + xrefs + " |\n")

def addExecutiveSummary():
    print("Adding executive summary")
    summary = r.cmd("Pn").split("\n")

    output = ""
    for line in summary:
        if "## Analysis" in line:
            break
        else:
            output += line + "\n"
    f.write(output)

def addBasicInfo():
    print("Adding basic info")
    filename = r.cmdj("ij")["core"]["file"]
    filesize = r.cmdj("ij")["core"]["size"]
    md5 = r.cmdj("itj")["md5"]
    sha1 = r.cmdj("itj")["sha1"]
    sha256 = r.cmdj("itj")["sha256"]
    arch = r.cmdj("ij")["bin"]["arch"]
    compiler = r.cmdj("ij")["bin"]["compiler"]
    static = r.cmdj("ij")["bin"]["static"]
    stripped = r.cmdj("ij")["bin"]["stripped"]

    f.write("""

---

### File Information

| Field  | Data  |
|---|---|
| Filename  | """ + filename + """  |
| File Size  | """ + str(filesize) + """  bytes  |
| MD5  | """ + md5 + """ |
| SHA1  | """ + sha1 + """ |
| SHA256  | """ + sha256 + """ |
| Architecture  | """ + arch + """ |
| Compiler | """ + compiler + """ |
| Statically linked  | """ + str(static) + """ |
| Stripped  | """ + str(stripped) + """ |
    """)



def addFunctionInfo():
    f.write("""

---

### Important Functions

""")
    for func in r.cmdj("aflj"):
        name = func["name"].split("[")[0]
        offset = hex(func["offset"])
        if "imp" in name:
            continue

        r.cmd("s " + offset)

        try:
            code = r.cmdj("pdgj")["code"].split("\n")
            comment = r.cmd("CC.")

            signature = "Signature not found"
            for line in code:
                if "(" in line and ")" in line and line[0] != " ":
                    signature = line
                    break

            if "report" in comment:
                f.write("**" + name + ":** " + signature + "\n\n")
                f.write("" + str(comment.replace("report: ", "") + "\n\n"))
        except:
            pass

main()
f.close()

def generateWebPage():
    html = ""
    with open("report.html", "r") as f:
        html = f.read()
    title = html.split("\n")[0].split("\"")[-1]
    html = "\n".join(html.split("\n")[1:])
    webpage = """
    <!DOCTYPE HTML>
<html>
	<head>
		<title>Chase Kanipe</title>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1" />
		<!--[if lte IE 8]><script src="assets/js/ie/html5shiv.js"></script><![endif]-->
		<link rel="stylesheet" href="../assets/css/main.css" />
		<!--[if lte IE 9]><link rel="stylesheet" href="assets/css/ie9.css" /><![endif]-->
		<!--[if lte IE 8]><link rel="stylesheet" href="assets/css/ie8.css" /><![endif]-->
	</head>
	<body>
		<!-- Header -->
			<div id="header" class="alt">
				<a class="logo" href="../index.html"><strong>Chase</strong> Kanipe</a>
			</div>

		<!-- Main -->
			<div id="main">

				<!-- Header -->
					<header>
						<h1""" + title + """
					</header>

				<!-- Content -->
					<section id="content" class="wrapper">
<p>
""" + html + """
</p>
					</section>

			</div>

		<!-- Footer -->
			<div id="footer">
				<ul class="joined-icons">
					<li><a href="#" class="icon fa-github"><span class="label">GitHub</span></a></li>
					<li><a href="#" class="icon fa-gitlab"><span class="label">GitLab</span></a></li>
					<li><a href="#" class="icon fa-linkedin"><span class="label">LinkedIn</span></a></li>
				</ul>
			</div>

		<!-- Scripts -->
			<script src="../assets/js/jquery.min.js"></script>
			<script src="../assets/js/jquery.dropotron.min.js"></script>
			<script src="../assets/js/jquery.scrollex.min.js"></script>
			<script src="../assets/js/skel.min.js"></script>
			<script src="../assets/js/util.js"></script>
			<!--[if lte IE 8]><script src="assets/js/ie/respond.min.js"></script><![endif]-->
			<script src="../assets/js/main.js"></script>

	</body>
</html>
    """
    with open("webpage.html", "w") as f:
        f.write(webpage)

os.system("cat report.md")
os.system("pandoc report.md > report.html")
generateWebPage()
os.system("rm report.html")

