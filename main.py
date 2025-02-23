import os 
import tempfile
from file_processing import clone_github_repo
from file_processing import load_and_index_files


def main():
    github_url = input("Nhập đường dẫn github URL: ")
    repo_name = github_url.split("/")[-1]
    print("Clone repo...")
    with tempfile.TemporaryDirectory() as local_path:
        if clone_github_repo(github_url, local_path):
            index, documents, file_type_count, filenames = load_and_index_files(local_path)
            if index is None:
                print("No documents were found to index. Existing !!!")
                exit()
            
            clone_github_repo(github_url, local_path)

        print("Repository close. Indexing files !!!")
        exit()