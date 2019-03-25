@echo off
setlocal

SET PYTHONPATH=%~dp0/../src;%PYTHONPATH%
python -m r2c.cli %*
