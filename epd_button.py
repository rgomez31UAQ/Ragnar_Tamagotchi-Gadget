# epd_button.py - Hardware button support for 2.7" e-Paper HAT
# GPIO pins: KEY1=5, KEY2=6, KEY3=13, KEY4=19
# Only active when a wide display (2.7"+) is detected

import logging
import threading
import time
import os

logger = logging.getLogger(__name__)

# GPIO pin assignments for 2.7" e-Paper HAT buttons
KEY1_PIN = 5
KEY2_PIN = 6
KEY3_PIN = 13
KEY4_PIN = 19

# Display pages
PAGE_MAIN = 0        # Default Ragnar display
PAGE_NETWORK = 1     # Network scanner stats
PAGE_VULN = 2        # Vulnerability scanner stats
PAGE_COUNT = 3       # Total number of pages (KEY4 is restart, not a page)


class EPDButtonListener:
    """Listens for hardware button presses on the 2.7" e-Paper HAT."""

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.current_page = PAGE_MAIN
        self.available = False
        self._stop_event = threading.Event()
        self._gpio = None
        self._thread = None

    def start(self):
        """Start the button listener thread. Only works on Pi with GPIO."""
        try:
            import RPi.GPIO as GPIO
            self._gpio = GPIO
            GPIO.setmode(GPIO.BCM)
            GPIO.setwarnings(False)

            for pin in (KEY1_PIN, KEY2_PIN, KEY3_PIN, KEY4_PIN):
                GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

            self.available = True
            self._thread = threading.Thread(target=self._poll_loop, daemon=True)
            self._thread.start()
            logger.info(f"EPD button listener started (GPIO {KEY1_PIN},{KEY2_PIN},{KEY3_PIN},{KEY4_PIN})")
        except ImportError:
            logger.info("RPi.GPIO not available - button listener disabled")
        except Exception as e:
            logger.warning(f"Could not start button listener: {e}")

    def stop(self):
        """Stop the button listener."""
        self._stop_event.set()
        if self._gpio:
            try:
                for pin in (KEY1_PIN, KEY2_PIN, KEY3_PIN, KEY4_PIN):
                    self._gpio.cleanup(pin)
            except Exception:
                pass

    def _poll_loop(self):
        """Poll buttons with debounce."""
        GPIO = self._gpio
        while not self._stop_event.is_set():
            try:
                if GPIO.input(KEY1_PIN) == 0:
                    self._on_key1()
                    self._wait_release(KEY1_PIN)
                elif GPIO.input(KEY2_PIN) == 0:
                    self._on_key2()
                    self._wait_release(KEY2_PIN)
                elif GPIO.input(KEY3_PIN) == 0:
                    self._on_key3()
                    self._wait_release(KEY3_PIN)
                elif GPIO.input(KEY4_PIN) == 0:
                    self._on_key4()
                    self._wait_release(KEY4_PIN)
            except Exception as e:
                logger.error(f"Button poll error: {e}")
            time.sleep(0.1)

    def _wait_release(self, pin):
        """Wait for button release with debounce."""
        GPIO = self._gpio
        while GPIO.input(pin) == 0 and not self._stop_event.is_set():
            time.sleep(0.05)
        time.sleep(0.2)  # debounce

    def _on_key1(self):
        """KEY1: Switch to Page 1 - Main display."""
        self.current_page = PAGE_MAIN
        logger.info("Button KEY1: Main display")

    def _on_key2(self):
        """KEY2: Switch to Page 2 - Network scanner stats."""
        self.current_page = PAGE_NETWORK
        logger.info("Button KEY2: Network scanner stats")

    def _on_key3(self):
        """KEY3: Switch to Page 3 - Vulnerability scanner stats."""
        self.current_page = PAGE_VULN
        logger.info("Button KEY3: Vuln scanner stats")

    def _on_key4(self):
        """KEY4: Restart Ragnar service."""
        logger.info("Button KEY4: Restarting Ragnar service...")
        threading.Thread(target=self._do_restart, daemon=True).start()

    @staticmethod
    def _do_restart():
        """Restart the ragnar service after a short delay."""
        time.sleep(1)
        os.system('systemctl restart ragnar.service')
