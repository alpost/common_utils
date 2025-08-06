""" 
Class GitUtils provides utility functions for Git operations. 
    It includes methods to clone a repository, check if a directory is a Git repository, switch to a specified branch commit version
    and validate vulnerability for a container.
"""

import os
import subprocess
import tempfile
from typing import Optional   
import argparse  
import time
import common_utils.logger_utils as lu
from urllib.parse import urlparse 
import threading 
import stat
import ssh_utils as su  




class GitUtils:
    def __init__(self):
        """
        Initialize the GitUtils class.
        """
        self._initialize_logger(level=None) 
        self.auth_params = self.initialize_auth_params() 
        self.thread_local = threading.local()
        #lu.log_environment(logger=self.logger, redact_sensitive=True)
        self.configure_github_auth()
        


    def _initialize_logger(self, level=None):
        """
        Initialize the logger for the class.
        :param level: Logging level (default: INFO).
        """
        lu.configure_logging()
        # Configure the logger for this module, we will use effective lvele if current in None
        self.logger = lu.configure_module_logging(module_name=self.__class__.__name__, log_level=level)
        self.logger.info("------GitUtils logger initialized.")

    def initialize_auth_params(self):
        """
        Initialize authentication parameters for Git operations.
        :return: Dictionary with authentication parameters.
        """
        auth_params = {
            "auth_method": os.getenv("AUTH_METHOD", "auto"),  
            "token": os.getenv("GITHUB_TOKEN", ""),
            "key_path": os.getenv("GITHUB_KEY_PATH", ""),
            "key_passphrase": os.getenv("GITHUB_KEY_PASSPHRASE", None),
            "git_domain": os.getenv("GITHUB_DOMAIN", "github.com")
        }
        self.logger.info(f"Authentication parameters initialized: {auth_params}")
        self.auth_method = auth_params.get("auth_method", "auto")
        return auth_params
    
    def _setup_ssh_auth(self):
            """
            Initializes SSH authentication using ssh-agent.
            - Starts a thread-local ssh-agent session
            - Loads the SSH key if not already loaded
            - Uses SSH_ASKPASS for non-interactive passphrase entry
            """
            self.logger.info("----------Setting up SSH authentication------------")
            ssh_key_path = self.auth_params.get("key_path")
            passphrase = self.auth_params.get("key_passphrase", None)
            askpass_path = None
            issue = None
            try: 
                 # Ensure SSH key path is set
                if not ssh_key_path:
                    raise ValueError("SSH key path is not set in authentication parameters.")
                
                ssh_key_path = os.path.expanduser(ssh_key_path)
                if not os.path.exists(ssh_key_path):
                    raise FileNotFoundError(f"SSH key not found at {ssh_key_path}")

                # Fix key permissions to 600 if needed
                try:
                    key_perms = oct(os.stat(ssh_key_path).st_mode & 0o777)
                    if key_perms != "0o600":
                        self.logger.warning(f"SSH key has incorrect permissions: {key_perms}, fixing to 0600")
                        os.chmod(ssh_key_path, 0o600)
                except Exception as e:
                    self.logger.warning(f"Could not check/fix key permissions: {str(e)}")

                # Kill any existing ssh-agent to start fresh
                if "SSH_AGENT_PID" in os.environ:
                    try:
                        pid = int(os.environ["SSH_AGENT_PID"])
                        self.logger.info(f"Terminating existing ssh-agent (PID: {pid})")
                        os.kill(pid, 15)  # SIGTERM
                    except (ValueError, ProcessLookupError) as e:
                        self.logger.warning(f"Could not terminate existing agent: {str(e)}")
                
                # Clear environment variables to start fresh
                for var in ["SSH_AUTH_SOCK", "SSH_AGENT_PID"]:
                    if var in os.environ:
                        del os.environ[var]

                # Start a new ssh-agent with proper output parsing
                self.logger.info("Starting new ssh-agent...")
                agent_output = subprocess.check_output(["ssh-agent", "-s"], text=True)
                self.logger.debug(f"\n\nssh-agent output: {agent_output}\n\n")
                
                # Better parsing of ssh-agent output - fix is here
                for line in agent_output.splitlines():
                    if "=" in line and ";" in line:
                        var_part = line.split(";")[0].strip()
                        if "=" in var_part:
                            var_name, var_value = var_part.split("=", 1)
                            os.environ[var_name] = var_value
                            self.logger.debug(f"Set {var_name}={var_value}")
                
                # Verify environment variables are set
                if "SSH_AUTH_SOCK" not in os.environ or "SSH_AGENT_PID" not in os.environ:
                    raise EnvironmentError("Failed to set SSH agent environment variables")
                    
                # Verify socket file exists
                auth_sock = os.environ.get("SSH_AUTH_SOCK")
                if not os.path.exists(auth_sock):
                    raise FileNotFoundError(f"SSH_AUTH_SOCK file not found at {auth_sock}")
                
                # Store agent environment in thread-local storage
                if not hasattr(self.thread_local, "agent_env"):
                    self.thread_local.agent_env = {
                        "SSH_AUTH_SOCK": os.environ["SSH_AUTH_SOCK"],
                        "SSH_AGENT_PID": os.environ["SSH_AGENT_PID"]
                    }

                # Set up direct Git SSH command as a reliable fallback
                os.environ["GIT_SSH_COMMAND"] = f"ssh -i {ssh_key_path} -o StrictHostKeyChecking=no"
                self.logger.info(f"Set GIT_SSH_COMMAND to use key {ssh_key_path}")

                # Check if key is already loaded
                try:
                    loaded_keys = subprocess.check_output(["ssh-add", "-l"], stderr=subprocess.PIPE, text=True)
                    if ssh_key_path in loaded_keys:
                        self.logger.info(f"SSH key {ssh_key_path} already loaded")
                        return  # Key already loaded
                except subprocess.CalledProcessError as e:
                    if e.returncode == 1:
                        self.logger.info("No keys currently loaded in ssh-agent")
                    else:
                        self.logger.warning(f"Error checking loaded keys: {e.stderr}")

                # Load key with optional SSH_ASKPASS
                passphrase = self.auth_params.get("key_passphrase", None)
                if passphrase:
                    with tempfile.NamedTemporaryFile("w", delete=False) as askpass_script:
                        askpass_script.write(f"#!/bin/sh\necho '{passphrase}'\n")
                        askpass_path = askpass_script.name
                    os.chmod(askpass_path, stat.S_IRWXU)

                    os.environ["SSH_ASKPASS"] = askpass_path
                    os.environ["GIT_ASKPASS"] = askpass_path
                    os.environ["DISPLAY"] = ":0"

                    try:
                        subprocess.check_call(["ssh-add", ssh_key_path], stdin=subprocess.DEVNULL)
                    finally:
                        os.remove(askpass_path)
                else:
                    subprocess.check_call(["ssh-add", ssh_key_path])

                self.logger.info(f"----------  No errors: SSH key {ssh_key_path} loaded successfully.")
            
            except OSError as e:
                self.logger.error(f"---------Failed to start ssh-agent: {str(e)}")
                issue = e
                
            except subprocess.CalledProcessError as e:
                self.logger.error(f"--------Failed to add SSH key: {str(e)}")
                issue = e
                
            except Exception as e:
                self.logger.error(f"--------Failed to set up SSH authentication: {str(e)}")
                issue = e
                
            finally:
                # Always clean up the askpass script if we created one
                if askpass_path and os.path.exists(askpass_path):
                    try:
                        os.remove(askpass_path)
                        self.logger.debug(f"Removed temporary askpass script: {askpass_path}")
                    except Exception as e:
                        self.logger.warning(f"Failed to remove askpass script: {str(e)}")
            
                if issue:
                    self.logger.info("---------Trying debug SSH authentication method")
                    # Make sure this is not an async function call
                    su.debug_ssh_add(ssh_key_path, passphrase)
                    
                    # Even if ssh-agent fails, Git operations can still work with GIT_SSH_COMMAND
                    if "GIT_SSH_COMMAND" in os.environ:
                        self.logger.info("Using GIT_SSH_COMMAND as fallback authentication method")
                        return
                    
                    # Re-raise the original exception if we couldn't set up any authentication
                    raise issue
            
    def clone_repo(self, repo_url: str, dest_dir: str) -> None:
        """
        Clone a Git repository to a specified directory.
        """
        if not repo_url:
            raise ValueError("Repository URL cannot be empty.")
        if not dest_dir:
            dest_dir = os.path.join(tempfile.gettempdir(), "git_clone")

        if not os.path.exists(dest_dir):
            os.makedirs(dest_dir)
        r_url = self.get_github_url(repo_url)
        self.logger.info(f"Cloning repository {r_url} to {dest_dir}")
        subprocess.run(["git", "clone", r_url, dest_dir], check=True)

    def is_git_repo(self, path: str) -> bool:
        """
        Check if the specified path is a Git repository.
        """
        return os.path.exists(os.path.join(path, ".git"))

    def switch_branch_commit(self, repo_path: str, branch_name: str, commit_hash: Optional[str] = None) -> None:
        """
        Switch to a specified branch and optionally to a specific commit in a Git repository.
        """
        if not self.is_git_repo(repo_path):
            raise ValueError(f"{repo_path} is not a valid Git repository.")
        
        subprocess.run(["git", "-C", repo_path, "checkout", branch_name], check=True)
        
        if commit_hash:
            subprocess.run(["git", "-C", repo_path, "checkout", commit_hash], check=True)

    def download_source_code(self, repo_url: str, dest_dir: str, branch_name: str = "main", commit_hash: Optional[str] = None) -> None:
        """
        Download source code from a Git repository.
        """
        self.clone_repo(repo_url, dest_dir)
        self.switch_branch_commit(dest_dir, branch_name, commit_hash)
        print(f"Source code downloaded to {dest_dir} on branch {branch_name} with commit {commit_hash if commit_hash else 'latest'}.")

    def configure_github_auth(self) -> None:
        """
        Configure and validates GitHub authentication for Git operations.
        
        Args:
            auth_method: Authentication method ('ssh', 'token', 'pat', 'auto')
            auth_params: Authentication parameters (depends on method)
                For 'token'/'pat': token, username (optional)
                For 'ssh': key_path, key_passphrase (optional)
        """
        self.logger.info(f"Configuring GitHub authentication using {self.auth_params["auth_method"]} method")
        
        if self.auth_method == "auto":
            # Try to determine the best authentication method
            if self.auth_params.get("token") and self.auth_params.get("token") != "":
                auth_method = "token"
            elif self.auth_params.get("key_path") and self.auth_params.get("key_path") != "":
                if os.path.exists(self.auth_params["key_path"]):
                    auth_method = "ssh"
                else:
                    self.logger.warning("SSH key path does not exist, falling back to token authentication")
                    raise ValueError(f"SSH key path {self.auth_params["key_path"]} does not exist, please provide a valid key path or use token authentication.")
            else:
                raise ValueError("No authentication method specified and no environment variables found.")
               
            self.auth_method = auth_method
        
        
        # Set up authentication based on the method
        if self.auth_method == "token" or self.auth_method == "pat":
            # Get token from params or environment
            github_token = self.auth_params.get("token", "")
            if not github_token or github_token == "":
                self.logger.warning("No GitHub token provided or found in environment variables")
                raise ValueError("GitHub token is required for token authentication.")
            else:
                self.logger.info("GitHub token configured successfully")
                
        elif self.auth_method == "ssh":
            self._setup_ssh_auth()
            self.logger.info("SSH authentication configured successfully")
        else:
            self.logger.error(f"Unsupported authentication method: {auth_method}")
            raise ValueError(f"Unsupported authentication method: {auth_method}")
    
        
    def get_github_url(self, repo_url: str) -> str:
        """
        Get the GitHub URL for a repository.
        
        Args:
            repo_name: Name of the repository (e.g., 'user/repo')
        
        Returns:
            str: Formatted GitHub URL
        """
        if not self.auth_params.get("git_domain"):
            raise ValueError("Git domain is not set in authentication parameters.")
        
        #parseout repo name from the url
        parsed_url = urlparse(repo_url)
        if parsed_url.scheme not in ["http", "https", "git"]:
            raise ValueError(f"Unsupported URL scheme: {parsed_url.scheme}. Expected 'http', 'https', or 'git'.")
        repo_name = parsed_url.path.lstrip("/")  # Remove leading slash
        #remove training .git if present
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]      
        if not repo_name:
            raise ValueError("Repository name cannot be empty.")
        
        # Construct the GitHub URL
        if self.auth_params["auth_method"] == "token" or self.auth_params["auth_method"] == "pat":
            # For token authentication, use HTTPS URL
            return f"https://{self.auth_params['git_domain']}/{repo_name}"
        elif self.auth_params["auth_method"] == "ssh":
            # For SSH, use the format   
            return f"git@{self.auth_params['git_domain']}:{repo_name}.git"
        else:
            raise ValueError(f"Unsupported authentication method: {self.auth_params['auth_method']}")
        
    def __del__(self):
        """Clean up resources when object is destroyed"""
        try:
            if hasattr(self, "auth_method") and self.auth_method == "ssh":
                self.cleanup_ssh_environment()
        except Exception as e:
            # Can't rely on logger in __del__
            print(f"Error during GitUtils cleanup: {str(e)}")

    def cleanup_ssh_environment(self):
        """
        Cleans up SSH environment variables and removes keys from the agent.
        This should be called when finished with Git operations or when shutting down.
        """
        self.logger.info("Cleaning up SSH environment and agent keys")
        
        # List of environment variables to clean up
        ssh_env_vars = [
            "SSH_AUTH_SOCK",
            "SSH_AGENT_PID",
            "SSH_ASKPASS",
            "DISPLAY"
        ]
        
        # Remove keys from ssh-agent if it's running
        if hasattr(self.thread_local, "agent_env") and self.thread_local.agent_env:
            try:
                # First, try to remove all keys
                subprocess.run(
                    ["ssh-add", "-D"], 
                    env=os.environ,
                    stderr=subprocess.PIPE,
                    check=False  # Don't raise an exception if it fails
                )
                self.logger.info("Removed all keys from SSH agent")
                
                # Kill the ssh-agent process
                if "SSH_AGENT_PID" in self.thread_local.agent_env:
                    agent_pid = self.thread_local.agent_env["SSH_AGENT_PID"]
                    try:
                        subprocess.run(
                            ["ssh-agent", "-k"], 
                            env=os.environ,
                            stderr=subprocess.PIPE,
                            check=False
                        )
                        self.logger.info(f"Terminated SSH agent (PID: {agent_pid})")
                    except Exception as e:
                        self.logger.warning(f"Failed to terminate SSH agent: {str(e)}")
                
                # Clear the thread-local agent environment
                delattr(self.thread_local, "agent_env")
                
            except Exception as e:
                self.logger.warning(f"Error while removing keys from SSH agent: {str(e)}")
        
        # Clean up environment variables
        for var in ssh_env_vars:
            if var in os.environ:
                del os.environ[var]
                self.logger.debug(f"Removed environment variable: {var}")
        
        # Remove any temporary askpass script if it exists
        if hasattr(self, "askpass_path") and os.path.exists(self.askpass_path):
            try:
                os.remove(self.askpass_path)
                self.logger.debug(f"Removed temporary askpass script: {self.askpass_path}")
                delattr(self, "askpass_path")
            except Exception as e:
                self.logger.warning(f"Failed to remove askpass script: {str(e)}")
        
        self.logger.info("SSH environment cleanup completed")
        
        

def main()->str:
    
    parser = argparse.ArgumentParser(description="Git Utilities CLI")
    parser.add_argument("--repo_url", type=str, required=True, help="URL of the Git repository to clone.")
    parser.add_argument("--dest_dir", type=str, required=False, help="Directory to clone the repository into.")
    parser.add_argument("--branch_name", type=str, default="main", help="Branch name to switch to after cloning.")
    parser.add_argument("--commit", type=str, help="Commit hash to switch to after cloning.")
    parser.add_argument("--action", type=str, choices=["clone", "switch", "download"], default="download", help="Action to perform: clone or switch branch/commit.")
    parser.add_argument("--log_level", type=str, default="INFO", help="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).")
    parser.add_argument("--git_key_path", type=str, default=None, help="Path to the SSH key for Git operations.")
    parser.add_argument("--git_key_passphrase", type=str, default=None, help="Passphrase for the SSH key (if required).")
    
    
    repo_url = parser.parse_args().repo_url
    dest_dir = parser.parse_args().dest_dir
    branch_name = parser.parse_args().branch_name
    commit_hash = parser.parse_args().commit
    key_path = parser.parse_args().git_key_path
    key_passphrase = parser.parse_args().git_key_passphrase
    log_level = parser.parse_args().log_level

    # Set environment variables for GitHub authentication
    os.environ["GITHUB_KEY_PATH"] = key_path if key_path else ""
    os.environ["GITHUB_KEY_PASSPHRASE"] = key_passphrase if key_passphrase else ""
    os.environ["GITHUB_TOKEN"] = ""  # Set to your GitHub token if needed
    os.environ["GITHUB_DOMAIN"] = "github.com"  # Set to your GitHub domain if needed
    os.environ["AUTH_METHOD"] = "ssh" if key_path else "token"  # Set to 'ssh' if key_path is provided, otherwise 'token'
    os.environ["LOG_LEVEL"] = log_level.upper()  if log_level else "INFO" # Set the log level from command line argument
    # Initialize GitUtils with the provided parameters

 
    git_utils = GitUtils()
    

    action = parser.parse_args().action
    # Set default destination directory if not provided
    if not dest_dir:
        dest_dir = f"./temp/src_code/{time.time()}"
    
    if action == "clone":
        git_utils.clone_repo(repo_url, dest_dir)
    elif action == "switch":
        git_utils.switch_branch_commit(dest_dir, branch_name, commit_hash)
    elif action == "download":
        git_utils.download_source_code(repo_url, dest_dir, branch_name, commit_hash)
    else:
        print("Invalid action specified.")
        raise ValueError("Action must be 'clone', 'switch', or 'download'.")
    return dest_dir

if __name__ == "__main__":
    main()

# Sample usage:
# python common_utils/git_utils.py --repo_url  "your_git_repo_url  --branch_name "main" --commit "commit_id" --action "download" --dest_dir "./temp/src_code" --log_level "DEBUG" --git_key_path "~/.ssh/id_rsa" --git_key_passphrase "your_passphrase"
# This will download the source code from the specified repository, switch to the specified branch and commit

# python common_utils/git_utils.py --repo_url "https://github.com/alpost/common_utils.git" --branch_name "main"  --action "download" --dest_dir "./temp/src_code" --log_level "DEBUG" --git_key_path "~/.ssh/tial_rsa" 