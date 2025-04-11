# Git Repository Cloner

This project provides a simple command-line tool for cloning Git repositories using either SSH keys or personal access tokens. It is designed to facilitate the cloning process while providing feedback on the progress of the operation.

## Features

- Clone repositories from GitHub or other Git hosting services.
- Support for SSH key authentication.
- Support for personal access token authentication.
- Progress bar to visualize the cloning process.

## Installation

To install the required dependencies, run:

```
pip install -r requirements.txt
```

## Usage

To use the repository cloner, you can create an instance of the `RepoCloner` class from the `clone_repo` module. Here is a basic example:

```python
from src.clone_repo import RepoCloner

repo_url = "https://github.com/username/repo.git"
ssh_key_path = "/path/to/ssh/key"  # Optional
token = "your_personal_access_token"  # Optional

cloner = RepoCloner(repo_url, ssh_key_path, token)
if cloner._is_valid_url():
    success = cloner._clone_repo()
    if success:
        print("Repository cloned successfully!")
    else:
        print("Failed to clone the repository.")
else:
    print("Invalid repository URL.")
```

## Progress Bar

The project includes a progress bar that updates during the cloning process. This feature enhances user experience by providing real-time feedback on the operation's progress.

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.