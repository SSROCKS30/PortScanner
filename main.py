import logging
from gui import PortScannerApp

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    app = PortScannerApp()
    app.mainloop()