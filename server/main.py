"""
SOC Platform Main Server
Single-process server with threaded workers
"""
from fastapi import FastAPI
from threading import Thread
import uvicorn
import logging
import os
import sys

# Try to load .env file if it exists
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Setup logging immediately to catch import errors and startup issues
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(threadName)-10s - %(name)-20s - %(levelname)-8s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("main")

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import API and workers with error handling
try:
    from api.ingest import app as ingest_app
    from workers.parser_worker import ParserWorker
    from workers.enricher_worker import EnricherWorker
    from workers.detector_worker import DetectorWorker
except ImportError as e:
    logger.error(f"Failed to import required modules: {e}")
    logger.error("Make sure all dependencies are installed: pip install -r requirements.txt")
    sys.exit(1)

# Configuration from environment
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/soc_platform")
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
THEHIVE_URL = os.getenv("THEHIVE_URL", "")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")
GEOIP_DB = os.getenv("GEOIP_DB", "/opt/geoip/GeoLite2-City.mmdb")

# Create main app
app = ingest_app

logger = logging.getLogger(__name__)

def start_workers():
    """Start all worker threads"""
    logger.info("=" * 60)
    logger.info("Starting SOC Platform Workers")
    logger.info("=" * 60)
    
    # Parser worker
    logger.info("Starting Parser Worker...")
    parser = ParserWorker(MONGO_URI)
    parser_thread = Thread(target=parser.run, daemon=True, name="Parser")
    parser_thread.start()
    logger.info("✓ Parser Worker started")
    
    # Enricher worker
    logger.info("Starting Enricher Worker...")
    enricher = EnricherWorker(MONGO_URI, GEOIP_DB)
    enricher_thread = Thread(target=enricher.run, daemon=True, name="Enricher")
    enricher_thread.start()
    logger.info("✓ Enricher Worker started")
    
    # Detector worker
    logger.info("Starting Detector Worker...")
    detector = DetectorWorker(MONGO_URI, REDIS_HOST, REDIS_PASSWORD if REDIS_PASSWORD else None)
    detector_thread = Thread(target=detector.run, daemon=True, name="Detector")
    detector_thread.start()
    logger.info("✓ Detector Worker started")
    
    # TheHive worker (optional)
    if THEHIVE_URL and THEHIVE_API_KEY:
        logger.info("Starting TheHive Worker...")
        try:
            from workers.thehive_worker import TheHiveWorker
            thehive = TheHiveWorker(MONGO_URI, THEHIVE_URL, THEHIVE_API_KEY)
            thehive_thread = Thread(target=thehive.run, daemon=True, name="TheHive")
            thehive_thread.start()
            logger.info("✓ TheHive Worker started")
        except Exception as e:
            logger.warning(f"TheHive Worker failed to start: {e}")
    else:
        logger.info("! TheHive integration disabled (no URL/API key)")
    
    logger.info("=" * 60)
    logger.info("All workers started successfully")
    logger.info("=" * 60)

def validate_environment():
    """Validate required environment variables"""
    errors = []
    
    if not MONGO_URI or "mongodb://" not in MONGO_URI:
        errors.append("MONGO_URI is invalid or missing")
    
    if not os.path.exists(GEOIP_DB):
        logger.warning(f"GeoIP database not found at {GEOIP_DB} - enrichment will be disabled")
    
    if errors:
        for error in errors:
            logger.error(f"Configuration error: {error}")
        logger.error("Fix configuration in .env file and restart")
        sys.exit(1)
    
    logger.info("✓ Environment validation passed")

def monitor_worker_health(threads):
    """Monitor worker thread health"""
    import time
    while True:
        time.sleep(60)  # Check every minute
        for name, thread in threads.items():
            if not thread.is_alive():
                logger.error(f"⚠️ Worker thread '{name}' has died!")
                # In production, this should trigger an alert

if __name__ == "__main__":
    try:
        logger.info("=" * 60)
        logger.info("SOC Platform Server Starting")
        logger.info("=" * 60)
        
        # Validate environment
        validate_environment()
        
        logger.info(f"MongoDB: {MONGO_URI}")
        logger.info(f"Redis: {REDIS_HOST}")
        logger.info(f"GeoIP DB: {GEOIP_DB}")
        logger.info(f"TheHive: {'Enabled' if THEHIVE_URL else 'Disabled'}")
        logger.info("=" * 60)
        
        # Start worker threads
        start_workers()
        
        # Start FastAPI server
        logger.info("Starting API server on port 5000...")
        logger.info("=" * 60)
        
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=5000,
            log_level="info",
            access_log=True
        )
    except Exception as e:
        logger.critical(f"FATAL ERROR during startup: {e}", exc_info=True)
        sys.exit(1)
