import os
from datetime import datetime, timedelta

from_email =""  # Sender Email Id
prev_window_title, prev_url, window_title, urlBuffer, is_browser, line_buffer="","","","",0,""
status=""
backspace_buffer_len, LOGFILEPATH=0,""
shift_on=False
ctrlc_pressed=0
# MINUTES_TO_LOG_TIME = 1
url_timer=None
mouse_timer=None
executable = False

def getdate():
    formatteddate = datetime.now().strftime("%H:%M:%S")
    return formatteddate

def log_local(print_str):
    if not print_str: return False

    try:
        with open(LOGFILEPATH, "a", encoding="utf-8") as fp:
            fp.write(print_str)
            print(print_str)
    except Exception as e:
        print("log_local error")
        print(print_str)
        print(e)
        return False
    backspace_buffer_len = 0
    return True

def set_status(val):
    global status
    status = val
    # print("set status="+str(val))


def get_status():
    global status
    return status


def set_ctrlc_pressed(val):
    global ctrlc_pressed
    ctrlc_pressed = val
    # print("set="+str(ctrlc_pressed))


def get_ctrlc_pressed():
    global ctrlc_pressed
    # print("get=" + str(ctrlc_pressed))
    return ctrlc_pressed

def f_test(val):
    if not executable:
        print(F"{val}")


def format_timedelta_to_HHMMSS(td):
    td_in_seconds = td.total_seconds()
    hours, remainder = divmod(td_in_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    hours = int(hours)
    minutes = int(minutes)
    seconds = int(seconds)
    if hours < 10:
        hours = "0{}".format(hours)
    if minutes < 10:
        minutes = "0{}".format(minutes)
    if seconds < 10:
        seconds = "0{}".format(seconds)
    return "{}:{}:{}".format(hours, minutes, seconds)