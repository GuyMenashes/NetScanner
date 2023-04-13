import pynput
import keyboard
hebrew_english_dict={'א':'t',
                     'ב':'c',
                     'ג':'d',
                     'ד':'s',
                     'ה':'v',
                     'ו':'u',
                     'ז':'z',
                     'ח':'j',
                     'ט':'y',
                     'י':'h',
                     'כ':'f',
                     'ל':'k',
                     'מ':'n',
                     'נ':'b',
                     'ס':'x',
                     'ע':'g',
                     'פ':'p',
                     'צ':'m',
                     'ק':'e',
                     'ר':'r',
                     'ש':'a',
                     'ת':',',
                     '/':'q',
                     "'":'w',
                     ',':"'",
                     'ף':';',
                     '[':']',
                     ']':'[',
                     ';':'`',
                     'ץ':'.',
                     '.':'/',
                     'ם':'o',
                     'ך':'l'                    
}
def a(key_event):
    if key_event.name in hebrew_english_dict.keys():
        print(key_event.name,hebrew_english_dict[key_event.name])
    else:
        print(key_event.name)

keyboard.hook(a)

while True:
    pass
