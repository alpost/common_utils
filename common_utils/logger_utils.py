# Log environment for debugging
import logging
import os
import json
import sys
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from pathlib import Path
import pandas as pd

DEFAULT_LOG_FILE_POSTFIX = f"{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}"

def configure_logging(
    log_level=None,
    log_file=None,
    log_format=None,
    log_rotation="time",
    console_output=True
):
    """
    Configure logging settings for the application
    
    Args:
        log_level: Logging level (DEBUG, INFO, etc). If None, uses ENV or defaults to INFO
        log_file: Path to log file. If None, uses ENV or defaults to app.log
        log_format: Log message format. If None, uses ENV or defaults to standard format
        log_rotation: Log rotation strategy ('size' or 'time'). Defaults to 'size'
        console_output: Whether to output logs to console. Defaults to True
        
    Returns:
        Logger: Configured logger instance
    """
    #check if root logger have been initialized
    root_logger = logging.getLogger()
    root_configured = len(root_logger.handlers) > 0
    if not root_configured:
        # Continue to configuration if root logger is not configured
        # Determine log level from arguments, environment, or default
        if log_level is None:
            log_level = os.getenv("LOG_LEVEL", "INFO").upper()
            logging.info(f"Using default log level: {log_level}")   
            
        # Convert string log level to logging constant
        numeric_level = getattr(logging, log_level, logging.INFO)
        
        # Determine log file path from arguments, environment, or default
        if log_file is None:
            #log file pattern appends timestamp date_time
            

            log_file = os.getenv("LOG_FILE", f"./logs/app_{DEFAULT_LOG_FILE_POSTFIX}.log")
        
        # Create directory for log file if it doesn't exist
        log_path = Path(log_file)
        if log_path.parent != Path('.'):
            log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Determine log format from arguments, environment, or default
        if log_format is None:
            log_format = os.getenv(
                "LOG_FORMAT", 
                '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
            )
        
        # Create formatter
        formatter = logging.Formatter(log_format)
        
        # Configure root logger
        root_logger.setLevel(numeric_level)
        
        # Remove existing handlers to prevent duplication
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Add file handler with appropriate rotation
        if log_rotation.lower() == "time":
            # Rotate log daily at midnight, keep 30 days of logs
            file_handler = TimedRotatingFileHandler(
                log_file,
                when='midnight',
                interval=1,
                backupCount=30
            )
        else:
            # Rotate log when it reaches 10MB, keep 5 backup files
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5
            )
        
        # Set formatter and level for file handler
        file_handler.setFormatter(formatter)
        file_handler.setLevel(numeric_level)
        root_logger.addHandler(file_handler)
        
        # Add console handler if requested
        if console_output:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            console_handler.setLevel(numeric_level)
            root_logger.addHandler(console_handler)
        
    # Create and return module-specific logger
    logger = logging.getLogger(__name__)
        
    # Log configuration details
    logger.info(f"Logging configured: level={log_level}, file={log_file}, rotation={log_rotation}")
    
    return logger

def configure_module_logging(
    module_name: str,
    log_level: str = None
):
    """
    Configure logging for a specific module with optional level override    
    log level: Logging level for the module. If None, uses root logger's level
    """
    module_logger = logging.getLogger(module_name)
    
    # If no specific level is provided, use the root logger's level
    if log_level is None:
        log_level = logging.getLogger().getEffectiveLevel()
    
    # Set the module logger's level
    module_logger.setLevel(log_level)
    # Ensure the module logger does not propagate to the root logger
        # Propagate to root logger if module level is >= root level
    root_logger = logging.getLogger()
    root_numeric_level = root_logger.getEffectiveLevel()
    
    if log_level and isinstance(log_level, str):
            module_numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    else:
        # If it's already a number, use it directly
        module_numeric_level = log_level
    
    module_logger.propagate = (module_numeric_level >= root_numeric_level)
    
    return module_logger




def dump_environment(redact_sensitive=True):
    """
    Dump environment variables to a dictionary, with optional redaction
    
    Args:
        redact_sensitive: Whether to redact sensitive values
        
    Returns:
        Dict: Environment variables
    """
    # Get all environment variables
    env_vars = {}
    
    # Filter out sensitive variables if requested
    sensitive_keys = ['PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'CREDENTIAL', 'AUTH']
    
    for key, value in os.environ.items():
        # Check if key contains any sensitive information
        if redact_sensitive and any(sensitive_key in key.upper() for sensitive_key in sensitive_keys):
            #use first 3 chars
            env_vars[key] = value[:3] + "***REDACTED***" if len(value) > 3 else "***REDACTED***"
            
        else:
            env_vars[key] = value
    
    # Sort by key for easier reading
    return dict(sorted(env_vars.items()))

def log_environment(logger: logging.Logger=logging.getLogger(__name__),level=logging.DEBUG, redact_sensitive=True):
    """Log all environment variables at the specified level"""
    env_vars = dump_environment(redact_sensitive)
    logger.log(level, f"Environment variables: {json.dumps(env_vars, indent=2)}")