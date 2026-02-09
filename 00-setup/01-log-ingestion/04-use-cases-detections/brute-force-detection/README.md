# Brute Force Login Detection

## Objective
Detect potential brute force login activity using Windows Event Logs.

## Data Source
- Windows Security Event ID 4625 (Failed Logon)

## SPL Query
```spl
index=wineventlog EventCode=4625
| stats count by Account_Name, src_ip
| where count > 5
