import win32gui
import pywinauto
import threading

import config
from config import *

def get_url_chrome():
    try:
        set_status("get_url_chrome()")

        app = pywinauto.Desktop(backend="uia")
        wrapper = app.windows(best_match=config.window_title, control_type="Pane", found_index=0)[0]  # title_re=".*Chrome.*"
        wrapper_url = wrapper.descendants(title="Address and search bar", control_type="Edit")[0]
        # return (wrapper.window_text() + "\n\t" + "URL=" + wrapper_url.get_value())
        current_url = wrapper_url.get_value()
        if current_url:
            return (wrapper.window_text() + "\n\t" + "Chrome URL=" + wrapper_url.get_value())
        else:
            return ""
    except Exception as e:
        # print("error")
        # print(e)
        pass
        return "ERROR"
        '''
        print("error")
        if (e.__str__() == "list index out of range"):
            return "list index out of range"
        else:
            print(e)
            '''
    return ""


def get_url_edge():
    try:
        set_status("get_url_edge()")

        app = pywinauto.Application(backend='uia')
        # app.connect(title_re=".*Microsoft​ Edge.*", found_index=0)
        app.connect(best_match=config.window_title, found_index=0)
        dlg = app.top_window()
        wrapper = dlg.child_window(title="App bar", control_type="ToolBar")
        wrapper_url = wrapper.descendants(control_type='Edit')[0]
        # return (wrapper_url.get_value())
        current_url = wrapper_url.get_value()
        if current_url:
            return (config.window_title + "\n\t" + "Edge URL=" + wrapper_url.get_value())
        else:
            return ""
    except Exception as e:
        # print(e)
        pass
        return "ERROR"


def get_url_firefox():
    try:
        set_status("get_url_firefox()")

        app = pywinauto.Desktop(backend="uia")
        wrapper = app.windows(best_match=config.window_title, found_index=0)[0]
        wrapper_url = wrapper.descendants(title="Search with Google or enter address", control_type="Edit")[0]

        # return (wrapper.window_text() + "\n\t" + "URL=" + wrapper_url.get_value())
        current_url = wrapper_url.get_value()
        if current_url:
            return (wrapper.window_text() + "\n\t" + "Firefox URL=" + wrapper_url.get_value())
        else:
            return ""
    except Exception as e:
        # print("Firefox error")
        # print(e)
        pass
        return "ERROR"



def get_url():

    if config.url_timer: config.url_timer.cancel()
    #global config.prev_window_title, config.prev_url, config.window_title, config.urlBuffer, config.is_browser, config.line_buffer
    try:

        config.window_title = win32gui.GetWindowText(win32gui.GetForegroundWindow())
        if config.window_title and (
                "- Google Chrome" in config.window_title or "— Mozilla Firefox" in config.window_title or "- Microsoft​ Edge" in config.window_title):
            config.is_browser = 1
            if config.window_title and config.window_title != config.prev_window_title:
                config.prev_window_title = config.window_title
            else:
                return
        else:
            config.is_browser = 0
            return
        if config.window_title and (
                "- Google Chrome" in config.window_title or "— Mozilla Firefox" in config.window_title or "- Microsoft​ Edge" in config.window_title):
            current_url = ""
            if "- Google Chrome" in config.window_title:
                current_url = get_url_chrome()
            elif "- Microsoft​ Edge" in config.window_title:
                current_url = get_url_edge()
            elif "— Mozilla Firefox" in config.window_title:
                current_url = get_url_firefox()
            if current_url == "ERROR": config.prev_window_title, current_url = "", ""

            current_url = current_url.strip()
            if current_url and config.prev_url != current_url:
                # print(getdate() + "\t\t" + config.window_title)
                config.urlBuffer = config.urlBuffer + getdate() + "\t" + config.line_buffer + current_url + "\n"
                config.line_buffer = ""
                if log_local(config.urlBuffer) == True: config.urlBuffer = ""

                # print(getdate() + "\t\t" + current_url)
                # print("\n")
                config.prev_url = current_url

    except Exception as e:
        print("error in get_url()")
        print(e)
    finally:
        # reschedule the timer
        if config.is_browser == 1:
            config.url_timer = threading.Timer(0.3, get_url)
        else:
            config.url_timer = threading.Timer(1, get_url)
        config.url_timer.start()