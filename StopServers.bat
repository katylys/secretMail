for /f "tokens=5" %%a in ('netstat -aon ^| find ":25" ^| find "LISTENING"') do taskkill /f /pid %%a
for /f "tokens=5" %%a in ('netstat -aon ^| find ":143" ^| find "LISTENING"') do taskkill /f /pid %%a

