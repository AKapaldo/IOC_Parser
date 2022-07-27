#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
This program is used for parsing IOC notices to run all time queries in Splunk.
"""

__author__ = "Andrew Kapaldo"
__copyright__ = "Copyright 2022"
__license__ = "GPL"
__version__ = "1.2"
__status__ = "Development"

import re
import tkinter as tk
from tkinter import ttk
from tkinter.filedialog import askopenfilename


#Main Function
def main():
    #Import opened file
    filetypes = (
        ('Text files', '*.txt'),
        ('All files', '*.*')
    )
    filename = askopenfilename(title='Open files',filetypes=filetypes)

    #Variables for program
    global final
    global email_final
    start = "**************** INDICATORS OF COMPROMISE"
    end = "********************"
    query = ""
    email_final = ""
    qstart = "earliest=1 latest=+10y ("
    qend = ")"
    terms = {
        "net": [],
        "hashes": [],
        "sites": [],
        "docs": [],
        "eaddress": []
    } 


    #Open the selected file and read in contents
    with open(filename, encoding="utf8") as f:
        file = f.read()

    #Remove everything around the start and end variables
    try:
        content = re.search(re.escape(start) + "(.*)" + re.escape(end), file, re.DOTALL).group(1).strip()
    except AttributeError:
        start = "*******"
        content = re.search(re.escape(start) + "(.*)", file, re.DOTALL).group(1).strip()

    #Get Hashes
    hashesSHA256 = re.findall(r'^[a-fA-F0-9]{64}$', content, re.MULTILINE)
    hashesSHA1 = re.findall(r'^[a-fA-F0-9]{40}$', content, re.MULTILINE)
    hashesMD5 = re.findall(r'^[a-fA-F0-9]{32}$', content, re.MULTILINE)

    #Get URLs
    urls = re.findall(r'^(?:(?:https?|ftp):\/\/)?[\w/\-?=%.]+\.[\w/\-&?=%.]+$', content, re.MULTILINE)

    #Get IPs
    ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', content)

    #Get Files
    files = re.findall(r'^(.*\.(?:doc|docx|docm|rtf|ppt|pptx|xls|xlsx|xlsm|xml|pdf|7z|zip|exe|msi|msp|iso|py|ps1|psm1|bat|cmd|sh|jar|js|vb))$', content, re.MULTILINE)

    #Get Email Addresses
    email = re.findall(r'([\w\.-]+@[\w\.-]+(?:\.[\w]+)+)', content)

    #See if IP is in URL list
    urls2 = [x for x in urls if x not in ips]

    #See if Docs in URL List
    site = [x for x in urls2 if x not in files]

    #Add URLs to dictionary
    for each in site:
        terms["sites"].append(each)

    #Add IPs to dictionary
    for ip in ips:
        search = "TERM(src_ip=" + ip + ") OR TERM(dest_ip=" + ip + ")"
        terms["net"].append(search)

    #Add hashes to dictionary
    for hash in hashesSHA256:
        terms["hashes"].append(hash)
    for hash2 in hashesSHA1:
        terms["hashes"].append(hash2)
    for hash3 in hashesMD5:
        terms["hashes"].append(hash3)

    #Add files to dictionary
    for doc in files:
        terms["docs"].append(doc)

    #Add emails to dictionary
    for address in email:
        terms["eaddress"].append(address)

    #Modify to add the search terms
    if len(terms["net"]) > 0:
        for y in range(len(terms["net"])):
            query += terms["net"][y] + " OR "

    if len(terms["docs"]) > 0:
        for y in range(len(terms["docs"])):
            query += "\"" + terms["docs"][y] + "\"" + " OR "

    if len(terms["hashes"]) > 0:
        for y in range(len(terms["hashes"])):
            query += "\"" + terms["hashes"][y] + "\"" + " OR "

    if len(terms["sites"]) > 0:
        for y in range(len(terms["sites"])):
            query += "\"" + terms["sites"][y] + "\"" + " OR "

    if len(terms["eaddress"]) > 0:
        for y in range(len(terms["eaddress"])):
            email_final += terms["eaddress"][y] + "; "

    #Remove the last " OR " and add the query start and end
    query = query[:-4]
    final = qstart + query + qend

    #Remove the last "; " for emails
    if email_final:
        email_final = email_final[:-2]
    else:
        email_final = "No email addresses listed in IOCs"

    #GUI Text box and contents
    text_box = tk.Text(
        splunk_frame,
        height=20,
        width=100
    )

    email_box = tk.Text(
    email_frame,
    height=3,
    width=100
    )

    text_box.place(x=10,y=10)
    text_box.insert('end', final)
    text_box.config(state='normal')

    email_box.place(x=10,y=10)
    email_box.insert('end', email_final)
    email_box.config(state='normal')

#Clear the clipboard and copy the Splunk result
def copy_to_clipboard():
    window.clipboard_clear()
    window.clipboard_append(final.rstrip())

#Clear the clipboard and copy the email result
def email_to_clipboard():
    window.clipboard_clear()
    window.clipboard_append(email_final.rstrip())

#Configure GUI Window
window = tk.Tk()
window.title("IOC Parser")
window.geometry('850x600')
window.config(bg='#202124')


splunk_frame = ttk.LabelFrame(window, text='Splunk Query')
splunk_frame.place(x=10, y=70, height=450, width=830)

email_frame = ttk.LabelFrame(window, text='O365 Email Query - Sender')
email_frame.place(x=10, y=430, height=100, width=830)

text_box = tk.Text(
        splunk_frame,
        height=20,
        width=100
    )

email_box = tk.Text(
    email_frame,
    height=3,
    width=100
)

text_box.place(x=10,y=10)
text_box.insert('end', "")
text_box.config(state='normal')

email_box.place(x=10,y=10)
email_box.insert('end', "")
email_box.config(state='normal')

#GUI Label and open dialog for file selection
label = tk.Label(text="Click \"Open...\" to select a file to parse for IOCs...", font=("Helvetica", 14), background="#202124", foreground="#dddddd", pady=20)
label.pack()

button_open = tk.Button(window, border=4 ,text="Open...", bg='#dddddd',command=main)
button_open.place(x=20, y=550)

#GUI Copy button
button_copy = tk.Button(window, border=4 ,text="Splunk To Clipboard", bg='#dddddd',command=copy_to_clipboard)
button_copy.place(x=80, y=550)

button_copy = tk.Button(window, border=4 ,text="Email To Clipboard", bg='#dddddd',command=email_to_clipboard)
button_copy.place(x=210, y=550)

#GUI Exit button
button_quit = tk.Button(window, border=4 ,text="Exit", bg='#dddddd',command=lambda: window.quit())
button_quit.place(x=330, y=550)


#Call the Main Loop
window.mainloop()
