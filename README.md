hi....
cd /opt/soc-platform
export $(cat .env | grep -v '^#' | xargs)
/opt/soc-platform/venv/bin/python3 /opt/soc-platform/main.py
