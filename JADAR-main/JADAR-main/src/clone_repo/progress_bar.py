import sys
import time
from typing import Optional
from threading import Thread

class ProgressBar:
    def __init__(self, total: int = 100, prefix: str = "Cloning", suffix: str = "Complete", length: int = 50, fill: str = "█", print_end: str = "\r"):
        """
        Initialize a progress bar.
        
        Args:
            total: Total iterations (default 100 for percentage)
            prefix: Prefix string
            suffix: Suffix string
            length: Character length of bar
            fill: Bar fill character
            print_end: End character (e.g. "\r", "\n")
        """
        self.total = total
        self.prefix = prefix
        self.suffix = suffix
        self.length = length
        self.fill = fill
        self.print_end = print_end
        self.progress = 0
        self._running = False
        self._spinner_thread = None
        
    def update(self, progress: int) -> None:
        """Update the progress bar."""
        self.progress = progress
        
        # Calculate percentage and filled length
        percent = ("{0:.1f}").format(100 * (progress / float(self.total)))
        filled_length = int(self.length * progress // self.total)
        
        # Create the bar
        bar = self.fill * filled_length + '-' * (self.length - filled_length)
        
        # Print the progress bar
        sys.stdout.write(f'\r{self.prefix} |{bar}| {percent}% {self.suffix}')
        sys.stdout.flush()
        
        # Print new line on complete
        if progress >= self.total:
            sys.stdout.write('\n')
            sys.stdout.flush()
            
    def start_indeterminate(self) -> None:
        """Start an indeterminate spinner for when progress can't be measured."""
        self._running = True
        self._spinner_thread = Thread(target=self._spin)
        self._spinner_thread.daemon = True
        self._spinner_thread.start()
    
    def stop_indeterminate(self) -> None:
        """Stop the indeterminate spinner."""
        self._running = False
        if self._spinner_thread and self._spinner_thread.is_alive():
            self._spinner_thread.join(timeout=1.0)
        sys.stdout.write('\r' + ' ' * (len(self.prefix) + self.length + 15) + '\r')
        sys.stdout.flush()
    
    def _spin(self) -> None:
        """Run the indeterminate spinner animation."""
        spinner = '|/-\\'
        idx = 0
        
        while self._running:
            sys.stdout.write(f'\r{self.prefix} {spinner[idx]} {self.suffix}')
            sys.stdout.flush()
            idx = (idx + 1) % len(spinner)
            time.sleep(0.1)