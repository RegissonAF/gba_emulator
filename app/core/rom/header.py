class Header:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


def read_header(file_path: str) -> Header:
    with open(file=file_path, mode="rb") as f:
        data = f.read()
        entry_point = data[0x100:0x104]
        nintendo_logo_top = data[0x104:0x11C]
        nintendo_logo_bot = data[0x11C:0x134]
        title = data[0x134:0x144]

    return Header(
        entry_point=entry_point,
        nintendo_logo_top=nintendo_logo_top,
        nintendo_logo_bot=nintendo_logo_bot,
        title=title,
    )
