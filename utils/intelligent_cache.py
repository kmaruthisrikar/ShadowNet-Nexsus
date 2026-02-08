"""
Intelligent Multi-Tier Caching System
Optimizes API usage and reduces costs
"""

import hashlib
import pickle
import time
from typing import Any, Optional, Dict
from pathlib import Path
import json


class IntelligentCache:
    """
    Multi-tier caching system for AI responses
    """
    
    def __init__(
        self, 
        cache_dir: str = "./cache",
        memory_cache_max_size: int = 1000,
        default_ttl: int = 3600
    ):
        """
        Initialize intelligent cache
        
        Args:
            cache_dir: Directory for disk cache
            memory_cache_max_size: Maximum entries in memory cache
            default_ttl: Default time-to-live in seconds
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # In-memory cache (fast, limited)
        self.memory_cache: Dict[str, Dict[str, Any]] = {}
        self.memory_cache_max_size = memory_cache_max_size
        self.default_ttl = default_ttl
        
        # Cache statistics
        self.hits = 0
        self.misses = 0
        self.evictions = 0
    
    def _generate_cache_key(self, *args, **kwargs) -> str:
        """
        Generate cache key from arguments
        
        Returns:
            SHA-256 hash of arguments
        """
        # Create deterministic key
        key_data = {
            'args': args,
            'kwargs': sorted(kwargs.items())
        }
        key_string = json.dumps(key_data, sort_keys=True).encode('utf-8')
        return hashlib.sha256(key_string).hexdigest()
    
    def get(self, key: str) -> Optional[Any]:
        """
        Retrieve from cache (memory first, then disk)
        
        Args:
            key: Cache key
        
        Returns:
            Cached value or None
        """
        # Try memory cache first (fastest)
        if key in self.memory_cache:
            entry = self.memory_cache[key]
            
            # Check if expired
            if time.time() < entry['expires_at']:
                self.hits += 1
                return entry['value']
            else:
                # Expired, remove from memory
                del self.memory_cache[key]
        
        # Try disk cache
        disk_path = self.cache_dir / f"{key}.cache"
        if disk_path.exists():
            try:
                with open(disk_path, 'rb') as f:
                    entry = pickle.load(f)
                
                # Check if expired
                if time.time() < entry['expires_at']:
                    # Promote to memory cache
                    self._set_memory_cache(key, entry['value'], entry['expires_at'])
                    self.hits += 1
                    return entry['value']
                else:
                    # Expired, remove from disk
                    disk_path.unlink()
            except Exception as e:
                print(f"Cache read error: {e}")
        
        self.misses += 1
        return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """
        Store in cache with TTL (time-to-live)
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds (None = use default)
        """
        if ttl is None:
            ttl = self.default_ttl
        
        expires_at = time.time() + ttl
        
        # Store in memory
        self._set_memory_cache(key, value, expires_at)
        
        # Store on disk for persistence
        try:
            disk_path = self.cache_dir / f"{key}.cache"
            entry = {
                'value': value,
                'expires_at': expires_at,
                'created_at': time.time()
            }
            
            with open(disk_path, 'wb') as f:
                pickle.dump(entry, f)
        except Exception as e:
            print(f"Cache write error: {e}")
    
    def _set_memory_cache(self, key: str, value: Any, expires_at: float):
        """
        Store in memory cache with LRU eviction
        
        Args:
            key: Cache key
            value: Value to cache
            expires_at: Expiration timestamp
        """
        # Evict if at capacity
        if len(self.memory_cache) >= self.memory_cache_max_size:
            # Evict oldest entry (simple LRU)
            oldest_key = next(iter(self.memory_cache))
            del self.memory_cache[oldest_key]
            self.evictions += 1
        
        self.memory_cache[key] = {
            'value': value,
            'expires_at': expires_at
        }
    
    def invalidate(self, key: str):
        """
        Invalidate specific cache entry
        
        Args:
            key: Cache key to invalidate
        """
        # Remove from memory
        if key in self.memory_cache:
            del self.memory_cache[key]
        
        # Remove from disk
        disk_path = self.cache_dir / f"{key}.cache"
        if disk_path.exists():
            disk_path.unlink()
    
    def invalidate_pattern(self, pattern: str):
        """
        Invalidate cache entries matching pattern
        
        Args:
            pattern: Pattern to match in cache keys
        """
        # Memory cache
        keys_to_delete = [k for k in self.memory_cache.keys() if pattern in k]
        for key in keys_to_delete:
            del self.memory_cache[key]
        
        # Disk cache
        for cache_file in self.cache_dir.glob("*.cache"):
            if pattern in cache_file.stem:
                cache_file.unlink()
    
    def clear(self):
        """Clear all cache entries"""
        self.memory_cache.clear()
        
        for cache_file in self.cache_dir.glob("*.cache"):
            cache_file.unlink()
    
    def cleanup_expired(self):
        """Remove expired entries from cache"""
        now = time.time()
        
        # Memory cache
        expired_keys = [
            k for k, v in self.memory_cache.items() 
            if now >= v['expires_at']
        ]
        for key in expired_keys:
            del self.memory_cache[key]
        
        # Disk cache
        for cache_file in self.cache_dir.glob("*.cache"):
            try:
                with open(cache_file, 'rb') as f:
                    entry = pickle.load(f)
                
                if now >= entry['expires_at']:
                    cache_file.unlink()
            except Exception:
                # Remove corrupted cache files
                cache_file.unlink()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache performance stats"""
        total_requests = self.hits + self.misses
        hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0
        
        # Calculate estimated cost savings
        # Assume $0.001 per API call saved
        estimated_savings = self.hits * 0.001
        
        return {
            'hits': self.hits,
            'misses': self.misses,
            'hit_rate': f"{hit_rate:.1f}%",
            'evictions': self.evictions,
            'memory_cache_size': len(self.memory_cache),
            'memory_cache_max': self.memory_cache_max_size,
            'estimated_cost_saved_usd': f"${estimated_savings:.2f}",
            'total_requests': total_requests
        }
