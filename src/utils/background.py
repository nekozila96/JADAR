import os
import sys
from typing import Tuple, Optional

# Đảm bảo có thể import từ thư mục src
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.LLM.config import LLMConfig, logger

def clear_screen():
    """Clear the terminal screen based on OS"""
    os.system('cls' if os.name == 'nt' else 'clear')

def display_header(title: str):
    """Display a formatted header"""
    print("\n" + "=" * 60)
    print(f"{title:^60}")
    print("=" * 60 + "\n")

def check_api_keys(prompt_for_missing: bool = False) -> Tuple[bool, bool]:
    """
    Check if API keys are available in environment variables
    
    Args:
        prompt_for_missing: If True, prompt user to input missing API keys
    
    Returns:
        Tuple[bool, bool]: (gemini_available, openai_available)
    """
    gemini_key = os.getenv("GEMINI_API_KEY")
    openai_key = os.getenv("OPENAI_API_KEY")
    
    # Prompt for missing API keys if requested
    if prompt_for_missing:
        if not gemini_key:
            print("\nGEMINI_API_KEY not found in environment variables.")
            key_input = input("Would you like to enter a Gemini API key now? (y/n): ").strip().lower()
            if key_input == 'y':
                gemini_key = input("Enter your Gemini API key: ").strip()
                if gemini_key:
                    # Store temporarily for this session
                    os.environ["GEMINI_API_KEY"] = gemini_key
                    print("Gemini API key stored for this session.")
        
        if not openai_key:
            print("\nOPENAI_API_KEY not found in environment variables.")
            key_input = input("Would you like to enter an OpenAI API key now? (y/n): ").strip().lower()
            if key_input == 'y':
                openai_key = input("Enter your OpenAI API key: ").strip()
                if openai_key:
                    # Store temporarily for this session
                    os.environ["OPENAI_API_KEY"] = openai_key
                    print("OpenAI API key stored for this session.")
    
    return bool(gemini_key), bool(openai_key)

def select_model(force_interactive: bool = False) -> Tuple[str, str]:
    """
    Interactive menu for model selection
    
    Args:
        force_interactive: Force interactive selection even if only one API key is available
        
    Returns:
        Tuple[str, str]: (model_type, model_name)
            model_type: 'gemini' or 'openai'
            model_name: Specific model name
    """
    # Check available API keys with option to input them
    gemini_available, openai_available = check_api_keys(prompt_for_missing=True)
    
    # If no API keys available after prompting, exit
    if not gemini_available and not openai_available:
        print("\nNo API keys available. Please set GEMINI_API_KEY or OPENAI_API_KEY in your environment.")
        print("You can also add these to your .env file.")
        if input("Continue without API keys? (y/n): ").strip().lower() != 'y':
            print("Exiting program...")
            sys.exit(0)
    
    # If only one API is available and not forcing interactive mode, auto-select it
    if not force_interactive:
        if gemini_available and not openai_available:
            logger.info("Only Gemini API key found. Auto-selecting Gemini.")
            return 'gemini', LLMConfig.GEMINI_MODEL_2
        elif openai_available and not gemini_available:
            logger.info("Only OpenAI API key found. Auto-selecting OpenAI.")
            return 'openai', LLMConfig.OPENAI_MODEL_1
    
    # Interactive selection
    while True:
        clear_screen()
        display_header("LLM MODEL SELECTION")
        
        print("Select LLM Type:")
        if gemini_available:
            print("[1] Google Gemini")
        else:
            print("[1] Google Gemini (API key not found)")
            
        if openai_available:
            print("[2] OpenAI GPT")
        else:
            print("[2] OpenAI GPT (API key not found)")
            
        print("[0] Exit")
        
        choice = input("\nEnter your choice (0-2): ").strip()
        
        if choice == '0':
            print("Exiting program...")
            sys.exit(0)
        
        # Gemini Models
        elif choice == '1':
            if not gemini_available:
                input("Gemini API key not found. Set GEMINI_API_KEY in your environment. Press Enter to continue...")
                continue
                
            clear_screen()
            display_header("GOOGLE GEMINI MODEL SELECTION")
            
            print("Select Gemini Model:")
            print(f"[1] {LLMConfig.GEMINI_MODEL_1}")
            print(f"[2] {LLMConfig.GEMINI_MODEL_2}")
            print(f"[3] {LLMConfig.GEMINI_MODEL_3}")
            print("[0] Back to LLM Type Selection")
            
            model_choice = input("\nEnter your choice (0-3): ").strip()
            
            if model_choice == '0':
                continue  # Go back to LLM type selection
            elif model_choice == '1':
                return 'gemini', LLMConfig.GEMINI_MODEL_1
            elif model_choice == '2':
                return 'gemini', LLMConfig.GEMINI_MODEL_2
            elif model_choice == '3':
                return 'gemini', LLMConfig.GEMINI_MODEL_3
            else:
                input("Invalid choice. Press Enter to try again...")
        
        # OpenAI Models
        elif choice == '2':
            if not openai_available:
                input("OpenAI API key not found. Set OPENAI_API_KEY in your environment. Press Enter to continue...")
                continue
                
            clear_screen()
            display_header("OPENAI GPT MODEL SELECTION")
            
            print("Select GPT Model:")
            print(f"[1] {LLMConfig.OPENAI_MODEL_1}")
            print(f"[2] {LLMConfig.OPENAI_MODEL_2}")
            print("[0] Back to LLM Type Selection")
            
            model_choice = input("\nEnter your choice (0-2): ").strip()
            
            if model_choice == '0':
                continue  # Go back to LLM type selection
            elif model_choice == '1':
                return 'openai', LLMConfig.OPENAI_MODEL_1
            elif model_choice == '2':
                return 'openai', LLMConfig.OPENAI_MODEL_2
            else:
                input("Invalid choice. Press Enter to try again...")
        
        else:
            input("Invalid choice. Press Enter to try again...")
            


if __name__ == "__main__":
    # Test the selection function
    model_type, model_name = select_model()
    print(f"\nYou selected: {model_type} - {model_name}")