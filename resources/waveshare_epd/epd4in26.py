# *****************************************************************************
# * | File        :   epd4in26.py
# * | Author      :   Waveshare team
# * | Function    :   Electronic paper driver
# * | Info        :
# *----------------
# * | This version:   V1.0
# * | Date        :   2023-12-18
# * | Info        :   python demo
# -----------------------------------------------------------------------------
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS OR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

import logging
from . import epdconfig

# Display resolution
EPD_WIDTH  = 800
EPD_HEIGHT = 480

logger = logging.getLogger(__name__)


class EPD:
    def __init__(self):
        self.is_initialized = False
        self.reset_pin = epdconfig.RST_PIN
        self.dc_pin    = epdconfig.DC_PIN
        self.busy_pin  = epdconfig.BUSY_PIN
        self.cs_pin    = epdconfig.CS_PIN
        self.width     = EPD_WIDTH
        self.height    = EPD_HEIGHT

    # -------------------------------------------------------------------------
    # Low-level helpers
    # -------------------------------------------------------------------------
    def reset(self):
        epdconfig.digital_write(self.reset_pin, 1)
        epdconfig.delay_ms(20)
        epdconfig.digital_write(self.reset_pin, 0)
        epdconfig.delay_ms(2)
        epdconfig.digital_write(self.reset_pin, 1)
        epdconfig.delay_ms(20)

    def send_command(self, command):
        epdconfig.digital_write(self.dc_pin, 0)
        epdconfig.digital_write(self.cs_pin, 0)
        epdconfig.spi_writebyte([command])
        epdconfig.digital_write(self.cs_pin, 1)

    def send_data(self, data):
        epdconfig.digital_write(self.dc_pin, 1)
        epdconfig.digital_write(self.cs_pin, 0)
        epdconfig.spi_writebyte([data])
        epdconfig.digital_write(self.cs_pin, 1)

    def send_data2(self, data):
        epdconfig.digital_write(self.dc_pin, 1)
        epdconfig.digital_write(self.cs_pin, 0)
        epdconfig.spi_writebyte2(data)
        epdconfig.digital_write(self.cs_pin, 1)

    def ReadBusy(self):
        logger.debug("e-Paper busy")
        while epdconfig.digital_read(self.busy_pin) == 0:  # 0: busy, 1: idle (epd4in26)
            epdconfig.delay_ms(10)
        logger.debug("e-Paper busy release")

    def TurnOnDisplay(self):
        self.send_command(0x12)  # DISPLAY_REFRESH
        epdconfig.delay_ms(100)
        self.ReadBusy()

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------
    def init(self):
        if epdconfig.module_init() != 0:
            return -1

        self.reset()

        self.ReadBusy()
        self.send_command(0x12)  # SWRESET
        self.ReadBusy()

        self.send_command(0x46)  # Auto Write RAM
        self.send_data(0xF7)
        self.ReadBusy()
        self.send_command(0x47)  # Auto Write RAM
        self.send_data(0xF7)
        self.ReadBusy()

        self.send_command(0x0C)  # Soft start setting
        self.send_data(0xAE)
        self.send_data(0xC7)
        self.send_data(0xC3)
        self.send_data(0xC0)
        self.send_data(0x40)

        self.send_command(0x01)  # Set MUX as 480
        self.send_data(0xDF)
        self.send_data(0x01)
        self.send_data(0x00)

        self.send_command(0x11)  # Data entry mode
        self.send_data(0x01)

        self.send_command(0x44)  # Set RAM X - address start / end position
        self.send_data(0x00)
        self.send_data(0x00)
        self.send_data(0x1F)
        self.send_data(0x03)

        self.send_command(0x45)  # Set RAM Y - address start / end position
        self.send_data(0xDF)
        self.send_data(0x01)
        self.send_data(0x00)
        self.send_data(0x00)

        self.send_command(0x3C)  # VBD
        self.send_data(0x01)

        self.send_command(0x18)  # Temperature sensor
        self.send_data(0x80)

        self.send_command(0x22)  # Load temperature and waveform setting
        self.send_data(0xB1)
        self.send_command(0x20)
        self.ReadBusy()

        self.send_command(0x4E)  # Set RAM X address counter
        self.send_data(0x00)
        self.send_data(0x00)
        self.send_command(0x4F)  # Set RAM Y address counter
        self.send_data(0xDF)
        self.send_data(0x01)

        self.is_initialized = True
        return 0

    def getbuffer(self, image):
        buf = [0xFF] * (int(self.width / 8) * self.height)
        image_monocolor = image.convert('1')
        imwidth, imheight = image_monocolor.size

        if imwidth == self.width and imheight == self.height:
            pixels = list(image_monocolor.getdata())
            for y in range(imheight):
                for x in range(imwidth):
                    if pixels[y * imwidth + x] == 0:
                        buf[int(x / 8) + y * int(imwidth / 8)] &= ~(0x80 >> (x % 8))
        elif imwidth == self.height and imheight == self.width:
            pixels = list(image_monocolor.getdata())
            for y in range(imheight):
                for x in range(imwidth):
                    newx = y
                    newy = self.height - x - 1
                    if pixels[x + y * imwidth] == 0:
                        buf[int(newx / 8) + newy * int(self.width / 8)] &= ~(0x80 >> (newx % 8))
        return buf

    def display(self, image):
        if not self.is_initialized:
            self.init()
        self.send_command(0x4E)
        self.send_data(0x00)
        self.send_data(0x00)
        self.send_command(0x4F)
        self.send_data(0xDF)
        self.send_data(0x01)

        self.send_command(0x24)
        self.send_data2(image)
        self.TurnOnDisplay()

    def displayPartial(self, image):
        self.display(image)

    def Clear(self):
        if not self.is_initialized:
            self.init()
        buf = [0xFF] * (int(self.width / 8) * self.height)
        self.send_command(0x4E)
        self.send_data(0x00)
        self.send_data(0x00)
        self.send_command(0x4F)
        self.send_data(0xDF)
        self.send_data(0x01)
        self.send_command(0x24)
        self.send_data2(buf)
        self.TurnOnDisplay()

    def sleep(self):
        self.send_command(0x10)  # Enter deep sleep
        self.send_data(0x01)
        epdconfig.delay_ms(100)
        epdconfig.module_exit()
