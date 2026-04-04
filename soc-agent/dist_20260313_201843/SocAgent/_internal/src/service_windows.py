import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
import sys
import os
import threading

# Add the parent directory to sys.path so we can import 'src' modules
if getattr(sys, 'frozen', False):
    # If the application is run as a bundle, the PyInstaller bootloader
    # extends the sys module by a flag frozen=True.
    current_dir = sys._MEIPASS if hasattr(sys, '_MEIPASS') else os.path.dirname(sys.executable)
    # in onedir mode, we are in the root of the dir, so src/ should be importable if we added it
    # But usually we just need to make sure CWD is right for config loading
    parent_dir = os.path.dirname(sys.executable) 
else:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)

if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from src.agent import main
from src.config import Config
from src.transport import Transport
from src.collectors.windows import WindowsCollector

class SocAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = "SocAgent"
    _svc_display_name_ = "Custom SOC Log Collection Agent"
    _svc_description_ = "Collects system logs and forwards them to the SOC."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.stop_requested = False
        self.collectors = []
        self.transport = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.stop_requested = True
        
        # Stop internal components
        if self.transport:
            self.transport.stop()
        for c in self.collectors:
            c.stop()

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, ''))
        self.main()

    def main(self):
        # Initialize components 
        try:
            # When frozen, config is expected to be in a 'config' folder next to the executable
            if getattr(sys, 'frozen', False):
                base_dir = os.path.dirname(sys.executable)
                os.chdir(base_dir)
            else:
                os.chdir(parent_dir)
            
            config = Config()
            self.transport = Transport(config)
            self.transport.start()
            
            w = WindowsCollector(config, self.transport)
            w.start()
            self.collectors.append(w)
            
            # Wait for stop signal
            win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)
            
        except Exception as e:
            servicemanager.LogErrorMsg(str(e))

if __name__ == '__main__':
    if len(sys.argv) == 1:
        # Check if we are running in a console
        if sys.stdin and sys.stdin.isatty():
            print("SOC Agent Windows Service")
            print("-------------------------")
            print("Usage:")
            print("  SocAgent.exe install    - Install the service")
            print("  SocAgent.exe remove     - Remove the service")
            print("  SocAgent.exe start      - Start the service")
            print("  SocAgent.exe stop       - Stop the service")
            print("  SocAgent.exe debug      - Run in debug mode (console)")
            print("\nTo install and start as a service, use 'setup.bat' or run as Admin.")
            input("\nPress Enter to exit...")
        else:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(SocAgentService)
            servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(SocAgentService)
