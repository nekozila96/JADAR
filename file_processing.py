
import os 
import subprocess
import uuid
from langchain.document_loaders import DirectoryLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter, RecursiveJsonSplitter
from utils import clean_and_tokenize
from rank_bm25 import BM25Okapi


def clone_github_repo(github_url, local_path):
    try:
        result = subprocess.run(
            ['git', 'clone', github_url, local_path],
            capture_output= True,
            text = True,
            check=True,
            timeout=300
        )       
        print("Clone thành công")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Lỗi khi clone: {e}")
        return False
    except FileNotFoundError as e:
        print("404 Link error")
        return False
    except subprocess.TimeoutExpired as e:
        print("Clone Time Out")
        return False
    except OSError as e:
        print(f"OS error: {e}")
        return False
    
