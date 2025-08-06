#   utilities to start ssh eagent and manage SSH keys.
import os
import subprocess
from typing import Optional
import logger_utils as lu
import threading
import logging



def log_env_var(var):
        _logger = lu.configure_module_logging(__name__, log_level="DEBUG")
        val = os.environ.get(var)
        if val:
            _logger.info(f"{var} is set: {val}")
        else:
            _logger.warning(f"{var} is not set")


def debug_ssh_add(key_path: str, path_phrase: Optional[str] = None) -> None :
    _logger = lu.configure_module_logging(__name__, log_level="DEBUG")
    
    _logger.info("----Debugging ssh-add process")
    _logger.info(f"----Key path: {key_path}")       
    _logger.info(f"----Passphrase: {'***REDACTED***' if path_phrase else 'None'}")  

    try:
        # Ensure ssh-agent is running
        if "SSH_AUTH_SOCK" not in os.environ or "SSH_AGENT_PID" not in os.environ:
            _logger.warning("------Starting ssh-agent...")
            agent_output = subprocess.check_output(["ssh-agent", "-s"], text=True)
            for line in agent_output.splitlines():
                if line.startswith("SSH_AUTH_SOCK") or line.startswith("SSH_AGENT_PID"):
                    key, _, value = line.partition("=")
                    os.environ[key] = value.rstrip(";")
        _logger.info("------ssh-agent is running: ")
        log_env_var("SSH_AUTH_SOCK")
        log_env_var("SSH_AGENT_PID")

        if not os.path.exists(key_path):
            raise FileNotFoundError(f"Key not found: {key_path}")
        
        # Optional: Validate permissions
        perms = oct(os.stat(key_path).st_mode & 0o777)
        if perms != "0o600":
            _logger.warning(f"Key permissions are {perms}, not 600")

        # Attempt ssh-add
        try:
            subprocess.check_call(["ssh-add", key_path], stdin=subprocess.DEVNULL)
            _logger.info("SSH key added successfully")
        except subprocess.CalledProcessError as e:
            _logger.error(f"ssh-add failed: {e}")
            _logger.info("Checking if key is already added...")
            output = subprocess.check_output(["ssh-add", "-l"], text=True)
            _logger.info(f"ssh-add -l output:\n{output}")

    except Exception as err:
        _logger.exception(f"Unhandled error while adding SSH key: {err}")