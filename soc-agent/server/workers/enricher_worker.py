"""
GeoIP Enrichment Worker
Enriches IP addresses with geographic information
"""
import geoip2.database
import geoip2.errors
import time
import logging
import os
from pymongo import MongoClient

class GeoIPEnricher:
    """Enrich IP addresses with GeoIP data"""
    
    def __init__(self, db_path="/opt/geoip/GeoLite2-City.mmdb"):
        try:
            self.reader = geoip2.database.Reader(db_path)
            self.cache = {}  # In-memory cache
            self.logger = logging.getLogger(__name__)
        except Exception as e:
            logging.error(f"Failed to load GeoIP database: {e}")
            self.reader = None
    
    def enrich(self, ip):
        """Enrich IP with GeoIP data (with caching)"""
        if not self.reader:
            return {"error": "GeoIP database not loaded"}
        
        # Skip private/localhost IPs
        if ip in ["127.0.0.1", "::1", "-", "0.0.0.0", None]:
            return {"private": True}
        
        # Check cache
        if ip in self.cache:
            cached = self.cache[ip]
            if cached["expires_at"] > time.time():
                return cached["data"]
        
        # Lookup in database
        try:
            response = self.reader.city(ip)
            
            data = {
                "country": response.country.name,
                "country_code": response.country.iso_code,
                "city": response.city.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
                "timezone": response.location.time_zone
            }
            
            # Cache for 24 hours
            self.cache[ip] = {
                "data": data,
                "expires_at": time.time() + 86400
            }
            
            # LRU eviction if cache grows too large
            if len(self.cache) > 1000:
                oldest = min(self.cache.items(), key=lambda x: x[1]["expires_at"])
                del self.cache[oldest[0]]
            
            return data
        
        except geoip2.errors.AddressNotFoundError:
            # Private or unknown IP
            return {"private": True}
        except Exception as e:
            self.logger.error(f"GeoIP lookup failed for {ip}: {e}")
            return {"error": str(e)}


class EnricherWorker:
    """Worker that enriches parsed logs"""
    
    def __init__(self, mongo_uri, geoip_db="/opt/geoip/GeoLite2-City.mmdb"):
        self.client = MongoClient(mongo_uri, maxPoolSize=20)
        self.db = self.client.get_database()
        self.geoip = GeoIPEnricher(geoip_db)
        self.logger = logging.getLogger(__name__)
        self.logger.info("Enricher Worker initialized")
    
    def run(self):
        """Main worker loop"""
        self.logger.info("Enricher Worker started")
        
        while True:
            try:
                # Get parsed logs without enrichment
                logs = list(self.db.raw_logs.find({
                    "processed": True,
                    "parsed_data": {"$exists": True},
                    "enriched": {"$ne": True}
                }).limit(50))
                
                if not logs:
                    time.sleep(2)
                    continue
                
                for log in logs:
                    try:
                        self._enrich_log(log)
                    except Exception as e:
                        self.logger.error(f"Error enriching log {log['_id']}: {e}")
                        # Mark as enriched anyway to avoid reprocessing
                        self.db.raw_logs.update_many(
                            {"_id": log["_id"]},
                            {"$set": {"enriched": True, "enrichment_error": str(e)}}
                        )
            
            except Exception as e:
                self.logger.error(f"Enricher worker error: {e}", exc_info=True)
                time.sleep(5)
    
    def _enrich_log(self, log):
        """Enrich a single log"""
        parsed = log.get("parsed_data", {})
        source_ip = parsed.get("source_ip")
        
        # Enrich source IP if present
        if source_ip:
            geo_data = self.geoip.enrich(source_ip)
            
            if not geo_data.get("error") and not geo_data.get("private"):
                # Add geo data to parsed_data
                parsed["geo"] = geo_data
                
                self.logger.debug(f"Enriched {source_ip}: {geo_data.get('country')}, {geo_data.get('city')}")
        
        # Update log with enriched data
        self.db.raw_logs.update_many(
            {"_id": log["_id"]},
            {"$set": {
                "parsed_data": parsed,
                "enriched": True
            }}
        )

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/soc_platform")
    GEOIP_DB = os.getenv("GEOIP_DB", "/opt/geoip/GeoLite2-City.mmdb")
    
    worker = EnricherWorker(MONGO_URI, GEOIP_DB)
    worker.run()
