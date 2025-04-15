import os
import sys
from typing import Tuple, Optional

# Đảm bảo có thể import từ thư mục src
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.LLM.config import LLMConfig, logger

# Global variables to track if we've already asked for keys
_already_prompted_for_gemini = False
_already_prompted_for_openai = False
_keys_loaded_from_env = False

def load_env_file():
    """Load environment variables from .env file if it exists"""
    global _keys_loaded_from_env
    
    if _keys_loaded_from_env:
        return
    
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), '.env')
    
    if os.path.exists(env_path):
        try:
            with open(env_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        key, value = line.split('=', 1)
                        # Only set if not already in environment
                        if key not in os.environ:
                            os.environ[key] = value
            _keys_loaded_from_env = True
            logger.info("Loaded environment variables from .env file")
        except Exception as e:
            logger.warning(f"Error loading .env file: {str(e)}")

# Load environment variables at module import time
load_env_file()

def clear_screen():
    """Clear the terminal screen based on OS"""
    os.system('cls' if os.name == 'nt' else 'clear')

def display_header(title: str):
    """Display a formatted header"""
    print("\n" + "=" * 60)
    print(f"{title:^60}")
    print("=" * 60 + "\n")

def manage_api_keys() -> Tuple[bool, bool]:
    """
    Manage API keys - view, add, or update them
    
    Returns:
        Tuple[bool, bool]: (gemini_available, openai_available)
    """
    # Make sure we've loaded from .env first
    if not _keys_loaded_from_env:
        load_env_file()
        
    gemini_key = os.getenv("GEMINI_API_KEY")
    openai_key = os.getenv("OPENAI_API_KEY")
    
    while True:
        clear_screen()
        display_header("API KEY MANAGEMENT")
        
        # Display current API key status
        print("Current API Keys:")
        print(f"1. Gemini API Key: {'Set' if gemini_key else 'Not Set'}")
        print(f"2. OpenAI API Key: {'Set' if openai_key else 'Not Set'}")
        print("\nOptions:")
        print("1. Set/Update Gemini API Key")
        print("2. Set/Update OpenAI API Key") 
        print("3. Save keys to .env file")
        print("0. Return to main menu")
        
        choice = input("\nEnter your choice (0-3): ").strip()
        
        if choice == '0':
            break
        elif choice == '1':
            gemini_key = input("\nEnter your Gemini API key (leave blank to keep current): ").strip()
            if gemini_key:
                os.environ["GEMINI_API_KEY"] = gemini_key
                print("Gemini API key updated for this session.")
                # Auto-save to avoid having to enter again
                save_choice = input("Would you like to save this key to .env file? (Y/n): ").strip().lower()
                if save_choice != 'n':  # Default to yes if user just presses Enter
                    save_keys_to_env(gemini_key, None)
                    global _already_prompted_for_gemini
                    _already_prompted_for_gemini = True  # Mark as prompted to avoid asking again
        elif choice == '2':
            openai_key = input("\nEnter your OpenAI API key (leave blank to keep current): ").strip()
            if openai_key:
                os.environ["OPENAI_API_KEY"] = openai_key
                print("OpenAI API key updated for this session.")
                # Auto-save to avoid having to enter again
                save_choice = input("Would you like to save this key to .env file? (Y/n): ").strip().lower()
                if save_choice != 'n':  # Default to yes if user just presses Enter
                    save_keys_to_env(None, openai_key)
                    global _already_prompted_for_openai
                    _already_prompted_for_openai = True  # Mark as prompted to avoid asking again
        elif choice == '3':
            if not gemini_key and not openai_key:
                print("\nNo API keys to save. Please set at least one key first.")
                input("Press Enter to continue...")
            else:
                save_keys_to_env(gemini_key, openai_key)
        else:
            input("Invalid choice. Press Enter to try again...")
    
    # Verify keys one more time before returning
    gemini_key = os.getenv("GEMINI_API_KEY")
    openai_key = os.getenv("OPENAI_API_KEY")
    return bool(gemini_key), bool(openai_key)

def save_keys_to_env(gemini_key: Optional[str], openai_key: Optional[str]):
    """
    Save API keys to .env file
    
    Args:
        gemini_key: Gemini API key
        openai_key: OpenAI API key
    """
    try:
        # Path to .env file
        env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), '.env')
        
        # Read existing content
        existing_lines = []
        gemini_line_exists = False
        openai_line_exists = False
        
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                for line in f:
                    if line.strip().startswith('GEMINI_API_KEY='):
                        if gemini_key:  # Only replace if we have a value
                            existing_lines.append(f"GEMINI_API_KEY={gemini_key}\n")
                        else:
                            existing_lines.append(line)  # Keep the existing line
                        gemini_line_exists = True
                    elif line.strip().startswith('OPENAI_API_KEY='):
                        if openai_key:  # Only replace if we have a value
                            existing_lines.append(f"OPENAI_API_KEY={openai_key}\n")
                        else:
                            existing_lines.append(line)  # Keep the existing line
                        openai_line_exists = True
                    else:
                        existing_lines.append(line)
        
        # Add keys that didn't exist before
        if gemini_key and not gemini_line_exists:
            existing_lines.append(f"GEMINI_API_KEY={gemini_key}\n")
        
        if openai_key and not openai_line_exists:
            existing_lines.append(f"OPENAI_API_KEY={openai_key}\n")
        
        # Write back to file
        with open(env_path, 'w') as f:
            f.writelines(existing_lines)
        
        # Set _keys_loaded_from_env to True since we've now written to the file
        global _keys_loaded_from_env
        _keys_loaded_from_env = True
        
        print("\n✅ API keys saved to .env file successfully.")
        input("Press Enter to continue...")
    
    except Exception as e:
        print(f"\n❌ Error saving API keys to .env file: {str(e)}")
        input("Press Enter to continue...")

def check_api_keys(prompt_for_missing: bool = False) -> Tuple[bool, bool]:
    """
    Check if API keys are available in environment variables
    
    Args:
        prompt_for_missing: If True, prompt user to input missing API keys (only once)
    
    Returns:
        Tuple[bool, bool]: (gemini_available, openai_available)
    """
    global _already_prompted_for_gemini, _already_prompted_for_openai
    
    # Make sure we've loaded from .env first
    if not _keys_loaded_from_env:
        load_env_file()
    
    gemini_key = os.getenv("GEMINI_API_KEY")
    openai_key = os.getenv("OPENAI_API_KEY")
    
    # Prompt for missing API keys if requested and not already prompted
    if prompt_for_missing:
        if not gemini_key and not _already_prompted_for_gemini:
            print("\nGEMINI_API_KEY not found.")
            key_input = input("Would you like to enter a Gemini API key now? (Y/n): ").strip().lower()
            if key_input != 'n':  # Default to yes
                gemini_key = input("Enter your Gemini API key: ").strip()
                if gemini_key:
                    # Store permanently to avoid asking again
                    os.environ["GEMINI_API_KEY"] = gemini_key
                    print("Gemini API key stored for this session.")
                    save_keys_to_env(gemini_key, None)
            _already_prompted_for_gemini = True
        
        if not openai_key and not _already_prompted_for_openai:
            print("\nOPENAI_API_KEY not found.")
            key_input = input("Would you like to enter an OpenAI API key now? (Y/n): ").strip().lower()
            if key_input != 'n':  # Default to yes
                openai_key = input("Enter your OpenAI API key: ").strip()
                if openai_key:
                    # Store permanently to avoid asking again
                    os.environ["OPENAI_API_KEY"] = openai_key
                    print("OpenAI API key stored for this session.")
                    save_keys_to_env(None, openai_key)
            _already_prompted_for_openai = True
    
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
        
        if input("Would you like to manage API keys now? (y/n): ").strip().lower() == 'y':
            gemini_available, openai_available = manage_api_keys()
        
        if not gemini_available and not openai_available:
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
        
        print("[3] Manage API Keys")    
        print("[0] Exit")
        
        choice = input("\nEnter your choice (0-3): ").strip()
        
        if choice == '0':
            print("Exiting program...")
            sys.exit(0)
        
        # Manage API Keys
        elif choice == '3':
            gemini_available, openai_available = manage_api_keys()
            continue
        
        # Gemini Models
        elif choice == '1':
            if not gemini_available:
                input("Gemini API key not found. Press Enter to return to menu and select 'Manage API Keys'...")
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
                input("OpenAI API key not found. Press Enter to return to menu and select 'Manage API Keys'...")
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