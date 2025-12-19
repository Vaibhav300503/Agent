import socket
import platform
import uuid

def get_hostname():
    return socket.gethostname()

def get_ip_address():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def get_os_type():
    return platform.system()

def get_agent_id():
    # Simple persistence based on hardware UUID or mac could be added here
    # For now, generating a deterministic ID based on hostname
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, get_hostname()))
