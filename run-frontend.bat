@echo off
echo Starting Network Device Mapper Frontend...
cd frontend
python -m http.server 3000
pause
