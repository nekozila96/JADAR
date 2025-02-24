import google.generativeai as genai 
import os 
import numpy as np
import glob
import faiss
from dotenv import load_dotenv

def get_embedding(text, model="models/embedding-001"):
    
    try:
        result = genai.embed_content(
            model=model,
            content=text,
            task_type="retrieval_query"
        )
        return result["embedding"]
    except Exception as e:
        print(f"Error getting embeeding: {e}")
        return None
    
def load_code(directory):
    code_files = []
    for ext in ['*.py', '*.js', '*.java', '*.cpp', '*.h', '*.ts', '*.go', '*.json', "*.html", "*.css"]:
        for filepath in glob.glob(os.path.join(directory, "**", ext), recursive=True):
            try:
                with open(file, "r", encoding="utf-8") as f:
                    content = f.read()
                code_files.append((content, filepath))
            except Exception as e:
                print(f"Error reading file {filepath}")
    return code_files

def create_embedding(code_files):
    texts = [content for content, _ in code_files]

    embedding = []
    for text in texts:
        embedding = get_embedding(text, task_type="retrieval_query")
        if embedding:
            embedding.append(embedding)
    embedding = np.array(embedding).astype("float32")

    dimesion = embedding.shape[1]
    index = faiss.IndexFlatL2(dimesion)
    index.add(embedding)

    return index, code_files

def search_code(query, index, code_files, top_k=5):
    query_embedding = get_embedding(query, task_type="retrieval_query")
    query_embedding = np.array(query_embedding).astype("float32")

    distance, indices = index.search(query_embedding, top_k)

    results = []
    for i in indices[0]:
        results.append(code_files[i])
    return results


