# Generate Test Windows Event Logs
# Run this as Administrator to create fake events that the agent will collect

Write-Host "Generating test Windows Event Logs..."

# Create a custom event source if it doesn't exist
$sourceName = "TestSOCAgent"
if (-not [System.Diagnostics.EventLog]::SourceExists($sourceName)) {
    New-EventLog -LogName Application -Source $sourceName
    Write-Host "Created event source: $sourceName"
}

# Generate 5 test events
for ($i = 1; $i -le 5; $i++) {
    Write-EventLog -LogName Application -Source $sourceName -EventId 1000 -EntryType Information -Message "Test SOC Agent Log Entry #$i - This is a test event generated at $(Get-Date)"
    Write-Host "Generated test event #$i"
    Start-Sleep -Milliseconds 500
}

Write-Host ""
Write-Host "Done! Generated 5 test events in the Application log."
Write-Host "The SOC Agent should collect these within the next 5 seconds (polling interval)."
Write-Host ""
Write-Host "To verify, check:"
Write-Host "1. Your ngrok console for incoming POST requests"
Write-Host "2. Ubuntu server logs at /var/log/soc-ingest/"
