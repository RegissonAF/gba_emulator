from enum import Enum

class LicenseCode(Enum):
    x00 = "None"
    x30 = "Viacom"
    x31 = "Nintendo"


f = open(file="data/Pokemon_Red.gb", mode='rb')

data = f.read()
entry_point = data[0x100:0x104]
nintendo_logo = data[0x104:0x134]
title = data[0x134:0x144]

title_str = str(title, 'utf-8')

f.close()

def start_text(entry_point, nintendo_logo, title):
    print(title_str)

start_text(entry_point=entry_point,nintendo_logo=nintendo_logo,title=title)