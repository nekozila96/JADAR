import os
import sys
from typing import Tuple, Optional

# Ensure can import from src directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.LLM.config import LLMConfig, logger

# Global variables to track if we've already asked for keys
_already_prompted_for_gemini = False
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

def manage_api_keys() -> bool:
    """
    Manage API keys - view, add, or update them
    
    Returns:
        bool: gemini_available
    """
    # Make sure we've loaded from .env first
    if not _keys_loaded_from_env:
        load_env_file()
        
    gemini_key = os.getenv("GEMINI_API_KEY")
    selected_model = os.getenv("GEMINI_MODEL", LLMConfig.GEMINI_MODEL_2)  # Default to model 2 if not set
    
    while True:
        clear_screen()
        display_header("API KEY & MODEL MANAGEMENT")
        
        # Display current API key status and selected model
        print("Current Settings:")
        print(f"1. Gemini API Key: {'Set' if gemini_key else 'Not Set'}")
        print(f"2. Selected Model: {selected_model}")
        print("\nOptions:")
        print("1. Set/Update Gemini API Key")
        print("2. Select Gemini Model")
        print("3. Save settings to .env file")
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
                    save_keys_to_env(gemini_key, selected_model)
                    global _already_prompted_for_gemini
                    _already_prompted_for_gemini = True  # Mark as prompted to avoid asking again
            input("Press Enter to continue...")
        elif choice == '2':
            # Display model selection menu
            print("\nSelect Gemini Model:")
            print(f"[1] {LLMConfig.GEMINI_MODEL_1}")
            print(f"[2] {LLMConfig.GEMINI_MODEL_2}")
            print(f"[3] {LLMConfig.GEMINI_MODEL_3}")
            
            model_choice = input("\nEnter your choice (1-3): ").strip()
            
            if model_choice == '1':
                selected_model = LLMConfig.GEMINI_MODEL_1
            elif model_choice == '2':
                selected_model = LLMConfig.GEMINI_MODEL_2
            elif model_choice == '3':
                selected_model = LLMConfig.GEMINI_MODEL_3
            else:
                print("Invalid choice. Keeping current model selection.")
                input("Press Enter to continue...")
                continue
                
            os.environ["GEMINI_MODEL"] = selected_model
            print(f"Model updated to: {selected_model}")
            save_choice = input("Would you like to save this model selection to .env file? (Y/n): ").strip().lower()
            if save_choice != 'n':  # Default to yes if user just presses Enter
                save_keys_to_env(gemini_key, selected_model)
            input("Press Enter to continue...")
        elif choice == '3':
            if not gemini_key:
                print("\nNo API key to save. Please set the key first.")
                input("Press Enter to continue...")
            else:
                save_keys_to_env(gemini_key, selected_model)
                input("Press Enter to continue...")
        else:
            input("Invalid choice. Press Enter to try again...")
    
    # Verify keys one more time before returning
    gemini_key = os.getenv("GEMINI_API_KEY")
    return bool(gemini_key)

def save_keys_to_env(gemini_key: Optional[str], model: Optional[str] = None):
    """
    Save API key and model selection to .env file
    
    Args:
        gemini_key: Gemini API key
        model: Selected Gemini model
    """
    try:
        # Path to .env file
        env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), '.env')
        
        # Read existing content
        existing_lines = []
        gemini_key_exists = False
        model_exists = False
        
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                for line in f:
                    if line.strip().startswith('GEMINI_API_KEY='):
                        if gemini_key:  # Only replace if we have a value
                            existing_lines.append(f"GEMINI_API_KEY={gemini_key}\n")
                        else:
                            existing_lines.append(line)  # Keep the existing line
                        gemini_key_exists = True
                    elif line.strip().startswith('GEMINI_MODEL='):
                        if model:  # Only replace if we have a value
                            existing_lines.append(f"GEMINI_MODEL={model}\n")
                        else:
                            existing_lines.append(line)  # Keep the existing line
                        model_exists = True
                    else:
                        # Keep all other lines
                        existing_lines.append(line)
        
        # Add key if it didn't exist before
        if gemini_key and not gemini_key_exists:
            existing_lines.append(f"GEMINI_API_KEY={gemini_key}\n")
        
        # Add model if it didn't exist before
        if model and not model_exists:
            existing_lines.append(f"GEMINI_MODEL={model}\n")
        
        # Write back to file
        with open(env_path, 'w') as f:
            f.writelines(existing_lines)
        
        # Set _keys_loaded_from_env to True since we've now written to the file
        global _keys_loaded_from_env
        _keys_loaded_from_env = True
        
        print("\n✅ Settings saved to .env file successfully.")
        input("Press Enter to continue...")
    
    except Exception as e:
        print(f"\n❌ Error saving settings to .env file: {str(e)}")
        input("Press Enter to continue...")

def check_api_keys(prompt_for_missing: bool = False) -> bool:
    """
    Check if API key is available in environment variables
    
    Args:
        prompt_for_missing: If True, prompt user to input missing API key (only once)
    
    Returns:
        bool: gemini_available
    """
    global _already_prompted_for_gemini
    
    # Make sure we've loaded from .env first
    if not _keys_loaded_from_env:
        load_env_file()
    
    gemini_key = os.getenv("GEMINI_API_KEY")
    
    # Prompt for missing API key if requested and not already prompted
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
                    save_keys_to_env(gemini_key)
            _already_prompted_for_gemini = True
    
    return bool(gemini_key)

def select_model(force_interactive: bool = False) -> Tuple[str, str]:
    """
    Interactive menu for model selection
    
    Args:
        force_interactive: Force interactive selection even if API key is available
        
    Returns:
        Tuple[str, str]: ('gemini', model_name)
            model_name: Specific model name
    """
    # Check available API key with option to input it
    gemini_available = check_api_keys(prompt_for_missing=True)
    
    # If no API key available after prompting, exit
    if not gemini_available:
        print("\nNo API key available. Please set GEMINI_API_KEY in your environment.")
        print("You can also add this to your .env file.")
        
        if input("Would you like to manage API key now? (y/n): ").strip().lower() == 'y':
            gemini_available = manage_api_keys()
        
        if not gemini_available:
            if input("Continue without API key? (y/n): ").strip().lower() != 'y':
                print("Exiting program...")
                sys.exit(0)
    
    # Read model preference from environment if available
    selected_model = os.getenv("GEMINI_MODEL")
    
    # Always display Gemini model selection menu if API key is available and forced interactive or no model selected
    if gemini_available and (force_interactive or not selected_model):
        # Display Gemini model selection menu
        clear_screen()
        display_header("GOOGLE GEMINI MODEL SELECTION")
        
        print("Select Gemini Model:")
        print(f"[1] {LLMConfig.GEMINI_MODEL_1}")
        print(f"[2] {LLMConfig.GEMINI_MODEL_2}")
        print(f"[3] {LLMConfig.GEMINI_MODEL_3}")
        print(f"[4] Edit API Key")
        print("[0] Exit")
        
        model_choice = input("\nEnter your choice (0-4): ").strip()  # Changed this to accept 0-4
        
        if model_choice == '0':
            print("Exiting program...")
            sys.exit(0)
        elif model_choice == '1':
            return 'gemini', LLMConfig.GEMINI_MODEL_1
        elif model_choice == '2':
            return 'gemini', LLMConfig.GEMINI_MODEL_2
        elif model_choice == '3':
            return 'gemini', LLMConfig.GEMINI_MODEL_3
        elif model_choice == '4':
            # Allow user to edit API key
            gemini_available = manage_api_keys()
            if not gemini_available:
                print("Exiting program...")
                sys.exit(0)
            return select_model(force_interactive=True)
        else:
            print("Invalid choice. Defaulting to Gemini model 2.")
            return 'gemini', LLMConfig.GEMINI_MODEL_2
    elif gemini_available and selected_model:
        # Use the pre-selected model from environment
        return 'gemini', selected_model
    else:
        print("\nNo Gemini API key available. Please set GEMINI_API_KEY in your environment.")
        print("Exiting program...")
        sys.exit(0)