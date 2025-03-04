import os
import json
from dotenv import load_dotenv
import google.generativeai as genai
from prompt import load_vulnerabilities, create_vulnerability_prompt
from typing import Dict, Any, List, Optional

dotenv.load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")
MODEL_NAME = os.getenv("MODEL_NAME", "gemini-2.0-flash")

if not API_KEY:
    raise ValueError("GEMINI_API_KEY không được tìm thấy trong file .env. Vui lòng thêm API key vào file .env.")

# Cấu hình API Gemini
genai.configure(api_key=API_KEY)


def analyze_vulnerability(vulnerability, prompt, results):

    try:
        # Khởi tạo model Gemini
        model = genai.GenerativeModel(MODEL_NAME)
        
        # Gửi prompt đến model
        response = model.generate_content(prompt)
        
        # Lấy kết quả phân tích
        analysis = response.text
        
        # Thêm kết quả vào danh sách
        results.append({
            "vulnerability": vulnerability,
            "analysis": analysis
        })
        
        # Ghi kết quả ra file ngay sau khi phân tích mỗi lỗ hổng
        with open("vulnerability_analysis.json", "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=4)
        
    except Exception as e:
        error_message = f"Lỗi khi gọi API Gemini: {str(e)}"
        print(error_message)
        
        # Thêm lỗi vào kết quả
        results.append({
            "vulnerability": vulnerability,
            "analysis": error_message
        })
        
        # Ghi kết quả ra file ngay cả khi có lỗi
        with open("vulnerability_analysis.json", "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        
        return error_message