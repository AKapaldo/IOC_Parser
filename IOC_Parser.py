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

f = open(filename, 'r')
content = f.read()
terms = {
    "net": [],
    "hashes": [],
    "sites": []
} 
query = ""
start = "Earliest=1 Latest=+10y ("
end = ")"

#Get URLs
urls = re.findall('(?:(?:https?|ftp):\/\/)?[\w/\-?=%.]+\.[\w/\-&?=%.]+', content)

#Get IPs
ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', content)

#See if IP is in URL list
site = [x for x in urls if x not in ips]

#Add URLs to dictionary
for each in site:
    terms["sites"].append(each)

#Add IPs to dictionary
for ip in ips:
    search = "TERM(src_ip=" + ip + ") OR TERM(dest_ip=" + ip + ")"
    terms["net"].append(search)

if len(terms["net"]) > 0:
    for y in range(len(terms["net"])):
        query += terms["net"][y] + " OR "

if len(terms["hashes"]) > 0:
    for y in range(len(terms["hashes"])):
        query += terms["hashes"][y] + " OR "

if len(terms["sites"]) > 0:
    for y in range(len(terms["sites"])):
        query += terms["sites"][y] + " OR "

query = query[:-4]
final = start + query + end

def copy_to_clipboard():
    """Copy current contents of text_entry to clipboard."""
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

#print(final)

window.mainloop()
