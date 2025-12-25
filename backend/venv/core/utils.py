"""
PhishRadar Utilities
Common helpers, decorators, logging, data loading, and security functions
"""
import warnings
warnings.filterwarnings("ignore", category=Warning)

import logging
import time
import json
import math
import re
import os
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, Optional
import validators

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("PhishRadar")

# Project root
PROJECT_ROOT = Path(__file__).parent.parent

# Data directory
DATA_DIR = PROJECT_ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)

def timing_decorator(func: Callable) -> Callable:
    """Decorator to measure function execution time"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()
        logger.debug(f"{func.__name__} executed in {end - start:.3f}s")
        return result
    return wrapper

def safe_execute(default_return: Any = None):
    """Decorator to safely execute functions with exception handling"""
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                logger.debug(f"Error in {func.__name__}: {e}")
                return default_return
        return wrapper
    return decorator

class DataManager:
    """Helper class for loading data files"""
    
    @staticmethod
    def load_json(filename: str) -> Any:
        file_path = DATA_DIR / filename
        if not file_path.exists():
            logger.warning(f"Data file not found: {file_path}")
            return None
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load {filename}: {e}")
            return None
    
    @staticmethod
    def load_text_lines(filename: str) -> list:
        file_path = DATA_DIR / filename
        if not file_path.exists():
            logger.warning(f"Data file not found: {file_path}")
            return []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Failed to load {filename}: {e}")
            return []

data_manager = DataManager()

class SecurityUtils:
    """Security-related utility functions"""
    
    @staticmethod
    def levenshtein_distance(s1: str, s2: str) -> int:
        """Calculate Levenshtein edit distance"""
        if len(s1) < len(s2):
            return SecurityUtils.levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    @staticmethod
    def calculate_similarity(s1: str, s2: str) -> float:
        """Calculate similarity ratio (0.0 to 1.0)"""
        if not s1 or not s2:
            return 0.0
        
        distance = SecurityUtils.levenshtein_distance(s1.lower(), s2.lower())
        max_len = max(len(s1), len(s2))
        if max_len == 0:
            return 1.0
        return 1.0 - (distance / max_len)

security_utils = SecurityUtils()

class URLValidator:
    """URL validation helper"""
    
    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Check if string is a valid URL"""
        if not url or not isinstance(url, str):
            return False
        return bool(validators.url(url.strip()))

url_validator = URLValidator()

class ReportGenerator:
    """Report formatting and saving"""
    
    @staticmethod
    def save_report(analysis_result: Dict, output_dir: str = "reports") -> Optional[str]:
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"phishradar_report_{timestamp}.json"
        filepath = Path(output_dir) / filename
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(analysis_result, f, indent=2, ensure_ascii=False)
            logger.info(f"Report saved: {filepath}")
            return str(filepath)
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
            return None
    
    @staticmethod
    def format_result(analysis_result: Dict) -> str:
        """Format result for console printing"""
        lines = [
            "="*80,
            f"PhishRadar Analysis Report",
            "="*80,
            f"URL: {analysis_result.get('url')}",
            f"Verdict: {analysis_result.get('verdict')}",
            f"Risk Score: {analysis_result.get('risk_score'):.2f}/100",
            f"Confidence: {analysis_result.get('confidence'):.1f}%",
            f"Scan Type: {analysis_result.get('scan_type')}",
            "-"*80,
            f"Threat Summary: {analysis_result.get('threat_summary')}",
            f"Recommendation: {analysis_result.get('recommendation')}",
            "="*80
        ]
        return "\n".join(lines)

report_generator = ReportGenerator()