"""
Enhanced Rate Limiter with Token Bucket Algorithm
Prevents API quota exhaustion and cost overruns
"""

import time
from collections import deque
from datetime import datetime, timedelta
from typing import Dict, Any


class RateLimiter:
    """
    Token bucket rate limiter for API calls
    """
    
    def __init__(
        self, 
        max_calls_per_minute: int = 15,  # Free tier limit
        max_calls_per_day: int = 1500
    ):
        """
        Initialize rate limiter
        
        Args:
            max_calls_per_minute: Maximum API calls per minute
            max_calls_per_day: Maximum API calls per day
        """
        self.max_per_minute = max_calls_per_minute
        self.max_per_day = max_calls_per_day
        
        # Sliding window for per-minute limiting
        self.minute_window = deque(maxlen=max_calls_per_minute)
        
        # Counter for daily limit
        self.daily_counter = 0
        self.daily_reset_time = datetime.now() + timedelta(days=1)
        
        # Statistics
        self.total_waits = 0
        self.total_wait_time = 0.0
    
    def wait_if_needed(self) -> float:
        """
        Block if rate limit would be exceeded
        
        Returns:
            Time waited in seconds
        """
        now = datetime.now()
        wait_time = 0.0
        
        # Reset daily counter if needed
        if now >= self.daily_reset_time:
            self.daily_counter = 0
            self.daily_reset_time = now + timedelta(days=1)
        
        # Check daily limit
        if self.daily_counter >= self.max_per_day:
            wait_seconds = (self.daily_reset_time - now).total_seconds()
            print(f"⏳ Daily API limit reached. Waiting {wait_seconds/3600:.1f} hours...")
            time.sleep(wait_seconds)
            self.daily_counter = 0
            self.daily_reset_time = datetime.now() + timedelta(days=1)
            wait_time += wait_seconds
        
        # Check per-minute limit
        while len(self.minute_window) >= self.max_per_minute:
            oldest_call = self.minute_window[0]
            time_since_oldest = now.timestamp() - oldest_call
            wait_needed = 60 - time_since_oldest
            
            if wait_needed > 0:
                print(f"⏳ Rate limit: waiting {wait_needed:.1f}s...")
                time.sleep(wait_needed)
                wait_time += wait_needed
                now = datetime.now()
            else:
                self.minute_window.popleft()
        
        # Record this call
        self.minute_window.append(now.timestamp())
        self.daily_counter += 1
        
        # Update statistics
        if wait_time > 0:
            self.total_waits += 1
            self.total_wait_time += wait_time
        
        return wait_time
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current rate limit stats"""
        now = datetime.now()
        time_until_reset = (self.daily_reset_time - now).total_seconds()
        
        return {
            'calls_this_minute': len(self.minute_window),
            'calls_today': self.daily_counter,
            'daily_limit': self.max_per_day,
            'daily_remaining': self.max_per_day - self.daily_counter,
            'next_daily_reset': self.daily_reset_time.isoformat(),
            'hours_until_reset': time_until_reset / 3600,
            'total_waits': self.total_waits,
            'total_wait_time_seconds': self.total_wait_time,
            'average_wait_time': (
                self.total_wait_time / self.total_waits 
                if self.total_waits > 0 else 0
            )
        }
    
    def can_make_call(self) -> bool:
        """
        Check if a call can be made without waiting
        
        Returns:
            True if call can be made immediately
        """
        now = datetime.now()
        
        # Check daily limit
        if now >= self.daily_reset_time:
            return True
        
        if self.daily_counter >= self.max_per_day:
            return False
        
        # Check per-minute limit
        if len(self.minute_window) >= self.max_per_minute:
            oldest_call = self.minute_window[0]
            time_since_oldest = now.timestamp() - oldest_call
            return time_since_oldest >= 60
        
        return True
