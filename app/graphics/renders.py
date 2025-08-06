import pygame
from app.graphics.config import GBC_HEIGHT, GBC_WIDTH

def render_nintendo_logo(top, bottom):
    surface = pygame.Surface((GBC_WIDTH, GBC_HEIGHT))
    surface.fill((195,195,195))
    counter_x = 0
    counter_y = 0
    for byte in top:
        for bit in format(byte, "08b"):
            print(counter_x, counter_y)
            surface.set_at((counter_x, counter_y), (255, 255, 255) if int(bit) else (0,0,0))
            counter_x += 1

            if counter_x % 4 == 0 and counter_x != 0:
                counter_y += 1
                counter_x -= 4

            if counter_y == 4:
                counter_y = 0
                counter_x += 4
    counter_x = 0
    counter_y = 4
    for byte in bottom:
        for bit in format(byte, "08b"):
            print(counter_x, counter_y)
            surface.set_at((counter_x, counter_y), (255, 255, 255) if int(bit) else (0,0,0))
            counter_x += 1

            if counter_x % 4 == 0 and counter_x != 0:
                counter_y += 1
                counter_x -= 4

            if counter_y == 8:
                counter_y = 4
                counter_x += 4
    return surface