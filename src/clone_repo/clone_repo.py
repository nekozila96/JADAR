import os
from typing import Optional
import urllib.parse
from .git_helpers import clone_repository, get_repo_name, is_git_repo
from .progress_bar import ProgressBar

class RepoCloner:
    def __init__(self, repo_url: str, ssh_key_path: Optional[str] = None, token: Optional[str] = None):
        """
        Initialize a repository cloner.
        
        Args:
            repo_url: URL of the Git repository to clone
            ssh_key_path: Path to SSH key for authentication (optional)
            token: Authentication token for private repositories (optional)
        """
        self.repo_url = repo_url
        self.ssh_key_path = ssh_key_path
        self.token = token
        self.repo_name = get_repo_name(self.repo_url)
        self.repo_path = None

    def _is_valid_url(self) -> bool:
        """Check if the repository URL is valid."""
        try:
            parsed = urllib.parse.urlparse(self.repo_url)
            return all([parsed.scheme, parsed.netloc])
        except ValueError:
            return False

    def clone(self, destination: Optional[str] = None) -> bool:
        """
        Clone the repository to the specified destination or current directory.
        
        Args:
            destination: Directory where the repository should be cloned (optional)
            
        Returns:
            bool: True if cloning was successful, False otherwise
        """
        if not self._is_valid_url():
            print(f"Invalid repository URL: {self.repo_url}")
            return False
            
        if destination:
            self.repo_path = os.path.join(destination, self.repo_name)
        else:
            self.repo_path = os.path.join(os.getcwd(), self.repo_name)
            
        # Check if destination already exists
        if os.path.exists(self.repo_path):
            if is_git_repo(self.repo_path):
                print(f"Repository already exists at {self.repo_path}. Skipping clone.")
                return True
            else:
                print(f"Directory {self.repo_path} already exists but is not a Git repository.")
                return False
        
        print(f"Cloning {self.repo_url} to {self.repo_path}...")
        success = clone_repository(
            repo_url=self.repo_url,
            destination=self.repo_path,
            ssh_key_path=self.ssh_key_path,
            token=self.token,
            show_progress=True
        )
        
        if success:
            print(f"Successfully cloned repository to {self.repo_path}")
        
        return success