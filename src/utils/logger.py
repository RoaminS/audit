# utils/logger.py

import logging
import os
import datetime

def setup_logging(log_directory="logs", log_level=logging.INFO):
    """
    Sets up a centralized logging configuration for the application.
    Logs will be written to a file with a timestamp and also to the console.

    Args:
        log_directory (str): The directory where log files will be stored.
        log_level (int): The minimum logging level to capture (e.DEBUG, logging.INFO, etc.).
    """
    # Create the log directory if it doesn't exist
    os.makedirs(log_directory, exist_ok=True)

    # Define the log file name with a timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = os.path.join(log_directory, f"hebbscan_{timestamp}.log")

    # Get the root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Clear any existing handlers to prevent duplicate logs
    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    # Create a file handler
    file_handler = logging.FileHandler(log_filename)
    file_handler.setLevel(log_level)
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)

    # Create a console handler (for streaming logs to stdout)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # Set up specific loggers if needed (e.g., for 'requests' library)
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)

    # Log a message to confirm setup
    root_logger.info(f"Logging configured. Logs will be saved to: {log_filename}")

# Example of how to get a logger in other modules:
# import logging
# logger = logging.getLogger(__name__)
# logger.info("This is an info message from my_module.")
