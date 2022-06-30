#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
This program is used for parsing IOC notices to run all time queries in Splunk.
"""

__author__ = "Andrew Kapaldo"
__copyright__ = "Copyright 2022"
__license__ = "GPL"
__version__ = "1.0"
__status__ = "Development"

import re
import tkinter as tk
from tkinter.filedialog import askopenfilename

window = tk.Tk()
window.title("IOC Parser")
window.geometry('850x600')
window.config(bg='#acacac')
greeting = tk.Label(text="Select a file to parse for IOCs...")
greeting.pack()


filename = askopenfilename() # show an "Open" dialog box and return the path to the selected file
flag = False
start = "**************** INDICATORS OF COMPROMISE **********************"
end = "****************************************************************"

with open(filename, encoding="utf8") as f:
    file = f.read()

content = re.search(re.escape(start) + "(.*)" + re.escape(end), file, re.DOTALL).group(1).strip()


terms = {
    "net": [],
    "hashes": [],
    "sites": [],
    "docs": []
} 
query = ""
qstart = "Earliest=1 Latest=+10y ("
qend = ")"

#Get Hashes
hashes = re.findall(r'\S{64}', content)

#Get URLs
urls = re.findall(r'(?:(?:https?|ftp):\/\/)?[\w/\-?=%.]+\.[\w/\-&?=%.]+', content)

#Get IPs
ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', content)

#Get Files
files = re.findall(r'^(.*\.(?:doc|docx|docm|rtf|ppt|pptx|xls|xlsx|xlsm|xml|pdf|7z|zip|exe|msi|msp|iso|py|ps1|psm1|bat|cmd|sh|jar|js|vb))$', content, re.MULTILINE)


#See if IP is in URL list
site = [x for x in urls if x not in ips]

#See if doc is in URL list
documents = [x for x in files if x not in urls]

#Add URLs to dictionary
for each in site:
    terms["sites"].append(each)

#Add IPs to dictionary
for ip in ips:
    search = "TERM(src_ip=" + ip + ") OR TERM(dest_ip=" + ip + ")"
    terms["net"].append(search)

#Add hashes to dictionary
for hash in hashes:
    terms["hashes"].append(hash)

for doc in documents:
    terms["docs"].append(doc)


if len(terms["net"]) > 0:
    for y in range(len(terms["net"])):
        query += terms["net"][y] + " OR "

if len(terms["docs"]) > 0:
    for y in range(len(terms["docs"])):
        query += "\"" + terms["docs"][y] + "\"" + " OR "

if len(terms["hashes"]) > 0:
    for y in range(len(terms["hashes"])):
        query += terms["hashes"][y] + " OR "

if len(terms["sites"]) > 0:
    for y in range(len(terms["sites"])):
        query += terms["sites"][y] + " OR "


query = query[:-4]
final = qstart + query + qend

def copy_to_clipboard():
    window.clipboard_clear()  # Optional.
    window.clipboard_append(final.rstrip())


text_box = tk.Text(
    window,
    height=20,
    width=100
)
text_box.pack(expand=True)
text_box.insert('end', final)
text_box.config(state='normal')

clp = tk.Button(window, border=4 ,text="Copy To Clipboard", bg='LightBlue1',command=copy_to_clipboard)
clp.place(x=20, y=500)

window.mainloop()
