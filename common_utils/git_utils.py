""" 
Class GitUtils provides utility functions for Git operations. 
    It includes methods to clone a repository, check if a directory is a Git repository, switch to a specified branch commit version
    and validate vulnerability for a container.
"""

import os
import subprocess
from typing import Optional   
import argparse  
import time
import logging
import common_utils.logger_utils as lu


class GitUtils:
    def __init__(self):
        """
        Initialize the GitUtils class.
        """
        self._initialize_logger(None)  

    def _initialize_logger(self, level=None):
        """
        Initialize the logger for the class.
        :param level: Logging level (default: INFO).
        """
        lu.configure_logging()
        if( level is None):
            level = logging.getLogger().level
        self.logger = lu.configure_module_logging(module_name=self.__class__.__name__, log_level=level)
        self.logger.info("GitUtils logger initialized.")

    def clone_repo(self, repo_url: str, dest_dir: str) -> None:
        """
        Clone a Git repository to a specified directory.
        """
        if not os.path.exists(dest_dir):
            os.makedirs(dest_dir)
        subprocess.run(["git", "clone", repo_url, dest_dir], check=True)

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

def main()->str:
    
    parser = argparse.ArgumentParser(description="Git Utilities CLI")
    parser.add_argument("--repo_url", type=str, required=True, help="URL of the Git repository to clone.")
    parser.add_argument("--dest_dir", type=str, required=False, help="Directory to clone the repository into.")
    parser.add_argument("--branch_name", type=str, default="main", help="Branch name to switch to after cloning.")
    parser.add_argument("--commit", type=str, help="Commit hash to switch to after cloning.")
    parser.add_argument("--action", type=str, choices=["clone", "switch", "download"], default="download", help="Action to perform: clone or switch branch/commit.")
    git_utils = GitUtils()
    
    repo_url = parser.parse_args().repo_url
    dest_dir = parser.parse_args().dest_dir
    branch_name = parser.parse_args().branch_name
    commit_hash = parser.parse_args().commit
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
# python common_utils/git_utils.py --repo_url  "your_git_repo_url  --branch_name "main" --commit "commit_id" --action "download"