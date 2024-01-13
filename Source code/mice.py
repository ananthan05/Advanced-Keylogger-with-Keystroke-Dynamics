
import mouse
import pyperclip
import pyautogui
import win32gui
import keyboard
import config
from config import *

from win32con import IDC_APPSTARTING, IDC_ARROW, IDC_CROSS, IDC_HAND, \
    IDC_HELP, IDC_IBEAM, IDC_ICON, IDC_NO, IDC_SIZE, IDC_SIZEALL, \
    IDC_SIZENESW, IDC_SIZENS, IDC_SIZENWSE, IDC_SIZEWE, IDC_UPARROW, IDC_WAIT

from win32gui import LoadCursor, GetCursorInfo

gl_int = 0
x1, y1, x2, y2 = 0, 0, 0, 0
selected_buffer, prev_selected = "", ""

DEFAULT_CURSORS = {
    LoadCursor(0, IDC_APPSTARTING): 'appStarting',
    LoadCursor(0, IDC_ARROW): 'Arrow', LoadCursor(0, IDC_CROSS): 'Cross',
    LoadCursor(0, IDC_HAND): 'Hand', LoadCursor(0, IDC_HELP): 'Help',
    LoadCursor(0, IDC_IBEAM): 'IBeam', LoadCursor(0, IDC_ICON): 'ICon',
    LoadCursor(0, IDC_NO): 'No', LoadCursor(0, IDC_SIZE): 'Size',
    LoadCursor(0, IDC_SIZEALL): 'sizeAll',
    LoadCursor(0, IDC_SIZENESW): 'sizeNesw',
    LoadCursor(0, IDC_SIZENS): 'sizeNs',
    LoadCursor(0, IDC_SIZENWSE): 'sizeNwse',
    LoadCursor(0, IDC_SIZEWE): 'sizeWe',
    LoadCursor(0, IDC_UPARROW): 'upArrow',
    LoadCursor(0, IDC_WAIT): 'Wait',
}


def get_current_cursor():
    curr_cursor_handle = GetCursorInfo()[1]
    # print(curr_cursor_handle)
    res = DEFAULT_CURSORS.get(curr_cursor_handle, 'None')
    return res


def on_drag(event):
    global x1, y1, x2, y2
    if str(event.button) != "left":
        x1, y1, x2, y2 = 0, 0, 0, 0
        return

    x, y = mouse.get_position()
    if str(event.event_type) == "down":
        # print('Pressed {0}'.format(event.button))
        x1 = x
        y1 = y
    elif str(event.event_type) == "up":
        x2 = x
        y2 = y
    else:
        return
    #set_status("on_drag()")
    call_selected_text = 0
    if (x2 > 0 and y2 > 0 and x1 != x2):
        # width = x2 - x1
        # height = y2 - y1
        # print("Dragged from (x1={}, y1={}) to (x2={}, y2={}, width={}, height={})".format(x1, y1, x2, y2, width, height))
        # print("on_drag")
        config.line_buffer += "<drag and drop>"
        if "<double click><drag and drop>" in config.line_buffer:
            config.line_buffer = config.line_buffer.replace("<double click><drag and drop>", "<double click>")
        elif "<left click><drag and drop>" in config.line_buffer:
            config.line_buffer = config.line_buffer.replace("<left click><drag and drop>", "<drag and drop>")
        call_selected_text = 1
    elif str(event.event_type) == "up":
        # print(get_current_cursor())
        if get_current_cursor() == "None" or config.shift_on == True or config.is_browser == 1: call_selected_text = 1
        # cursor_val = win32gui.GetCursorInfo()[1]
        # if(cursor_val==197199 or cursor_val ==3343359): get_selected_text()
    if call_selected_text == 0: return
    try:
        set_ctrlc_pressed(1)
        get_selected_text()
    finally:
        set_ctrlc_pressed(0)


def on_click():
    print("single click")


def on_double_click():
    global x1, y1, x2, y2
    x1, y1, x2, y2 = 0, 0, 0, 0
    config.line_buffer += "<double click>"
    # print("double_click")
    # get_selected_text()

def print_hotkey():
    print("Hotkey pressed!")
def get_selected_text():
    global x1, y1, x2, y2, selected_buffer, prev_selected
    x1, y1, x2, y2 = 0, 0, 0, 0
    set_status("get_selected_text begin")
    clipstr = pyperclip.paste()
    try:
        # set_ctrlc_pressed(1)
        set_status("get_selected_text before ctrl+c")
        #keyboard.add_hotkey("ctrl+c",print_hotkey)

        pyautogui.hotkey('ctrl', 'c')
        # set_ctrlc_pressed(0)
        set_status("get_selected_text after ctrl+c")
        selected_text = pyperclip.paste()
        set_status("get_selected_text after after paste()")
        pyperclip.copy(clipstr)
        #keyboard.clear_all_hotkeys
        set_status("get_selected_text after after copy()")
        if selected_text and prev_selected != selected_text:  # and selected_text != clipstr:
            prev_selected = selected_text
            config.window_title = win32gui.GetWindowText(win32gui.GetForegroundWindow())
            config.window_title = '[WindowName: ' + config.window_title + ']: '
            selected_buffer = selected_buffer + getdate() + "\t" + config.window_title + config.line_buffer + "\n\t<SELECTED TEXT>" + selected_text.strip() + "\n"
            config.line_buffer = ''
            if log_local(selected_buffer): selected_buffer = ""


    except Exception as e:
        print("error in get_selected_text")
        print(e)
    finally:
        dummy = ""
        # set_ctrlc_pressed(0)
        set_status("get_selected_text end")
        # pyperclip.copy(clipstr)
        # set_ctrlc_pressed(0)
        # print("get_selected_text()=" + str(get_ctrlc_pressed()))


def OnMouseEvent(event):
    # `mouse.ButtonEvent`,`mouse.WheelEvent` or `mouse.MoveEvent`.
    # ButtonEvent = namedtuple('ButtonEvent', ['event_type', 'button', 'time'])
    # WheelEvent = namedtuple('WheelEvent', ['delta', 'time'])
    # MoveEvent = namedtuple('MoveEvent', ['x', 'y', 'time'])

    if isinstance(event, mouse.ButtonEvent):

        #data = 'Button:' + str(event.button)
        #data += '\ttype:' + str(event.event_type)
        # print(data) #Button:left	type:down   Button:left	type:up
        if str(event.event_type) == "up":
            if config.line_buffer[ len(config.line_buffer) - len(F"<{event.button} click>"):] != F"<{event.button} click>":
                config.line_buffer += F"<{event.button} click>"
                if "<left click><double click><left click>" in config.line_buffer:
                    config.line_buffer = config.line_buffer.replace("<left click><double click><left click>","<double click>")

        on_drag(event)
    elif isinstance(event, mouse.MoveEvent):
        global x2, y2
        # data = 'x=' + str(event.x)
        # data += '\ty=' + str(event.y)
        x2, y2 = 0, 0
        # x2 = event.x
        # y2 = event.y
        # print(data)
        if config.line_buffer[len(config.line_buffer) - len(F"<mouse move>"):] != F"<mouse move>":
            config.line_buffer += F"<mouse move>"
    elif isinstance(event, mouse.WheelEvent):
        if event.delta == 1.0:
            data = "<wheel Up>"
        else:
            data = "<wheel Down>"
        # print(data)
        if config.line_buffer[len(config.line_buffer) - len(data):] != data:
            config.line_buffer += data
            if data +"<mouse move>" in config.line_buffer == "":
                config.line_buffer = config.line_buffer.replace(data +"<mouse move>", data)


    return


# Hook the mouse
def mouse_start():
    try:
        mouse.on_double_click(on_double_click)
        # mouse.on_click( on_click )
        mouse.hook(OnMouseEvent)
        mouse.wait(button=None)
    except Exception as e:
        print(e)

