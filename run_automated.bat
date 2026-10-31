@echo off
cd /d "%~dp0"
py -3 terminal_runner.py --auto --profile balanced --no-scrapoxy --no-vpngate
