import pygame
from app.core.rom.header import read_header
from app.graphics.config import SCALE, WINDOW_HEIGHT, WINDOW_WIDTH
from app.graphics.renders import render_nintendo_logo

def window():
    # pygame setup
    pygame.init()




    window = pygame.display.set_mode((WINDOW_WIDTH, WINDOW_HEIGHT))
    clock = pygame.time.Clock()
    running = True

    header = read_header("data/Pokemon_Red.gb")

    while running:
        # poll for events
        # pygame.QUIT event means the user clicked X to close your window
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                running = False

        # fill the screen with a color to wipe away anything from last frame
        window.fill("white")

        # RENDER YOUR GAME HERE
        screen = render_nintendo_logo(header.nintendo_logo_top, header.nintendo_logo_bot)
        transformed = pygame.transform.scale_by(screen, SCALE)
        window.blit(transformed, (0,0))
        
        # flip() the display to put your work on screen
        pygame.display.flip()

        clock.tick(60)  # limits FPS to 60

    pygame.quit()