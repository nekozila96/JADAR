
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
        print("Output: ", result.stdout)
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
    
def load_and_index_files(repo_path):
    extensions = ['java', 'xml', 'properties', 'gradle', 'sh', 'json']
    file_type_counts = {}
    documents_dict = {}

    for ext in extensions:
        glob_pattern = f"**/*.{ext}"
        try:
            loader = None
            loader = DirectoryLoader(repo_path, glob = glob_pattern)
        
            loaded_documents = loader.load() if callable(loader.load) else []
            if loaded_documents:
                file_type_counts[ext] = len(loaded_documents)
                for doc in loaded_documents:
                    file_path = doc.metadata['source']
                    relative_path = os.path.relpath(file_path, repo_path)
                    file_id = str(uuid.uuid4())
                    doc.metadata['source'] = relative_path
                    doc.metadata['file_id'] = file_id
                    documents_dict[file_id] = doc
        except Exception as e:
            print(f"Error loading {ext} files: {e}")
            continue

    text_splitter = RecursiveCharacterTextSplitter(chunk_size=3000, chunk_overlap=200)

    split_documents = [] 
    for file_id, orginal_doc in documents_dict.items():
        split_docs = text_splitter.split_documents([orginal_doc])
        for split_doc in split_docs:
            split_doc.metadata['file_id'] = orginal_doc.metadata['file_id']
            split_doc.metadata['source'] = orginal_doc.metadata['source']

        split_documents.extend(split_docs)

    index = None
    if split_documents:
        tokenized_docs = [clean_and_tokenize(doc.page_content) for doc in split_documents]
        index = BM250kapi(tokenized_docs)
    return index, split_documents, file_type_counts, [doc.metadata['source'] for doc in split_documents]