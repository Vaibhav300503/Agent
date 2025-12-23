# Direct Test - Send a fake log to the server
# This simulates what the agent does

$serverUrl = "https://carmela-unpublished-lou.ngrok-free.dev/api/v1/logs"
$apiToken = "Server@123"

$testLog = @{
    timestamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    hostname   = $env:COMPUTERNAME
    os_type    = "Windows"
    ip_address = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" } | Select-Object -First 1).IPAddress
    log_source = "TestScript"
    message    = "TEST LOG - Manual test at $(Get-Date)"
    event_id   = 9999
    level      = "Information"
}

$body = @($testLog) | ConvertTo-Json -Depth 10

Write-Host "Sending test log to: $serverUrl"
Write-Host "Using token: $apiToken"
Write-Host ""
Write-Host "Payload:"
Write-Host $body
Write-Host ""

try {
    $response = Invoke-WebRequest -Uri $serverUrl `
        -Method POST `
        -Headers @{
        "Authorization" = "Bearer $apiToken"
        "Content-Type"  = "application/json"
    } `
        -Body $body `
        -UseBasicParsing

    Write-Host "SUCCESS! Server responded with: $($response.StatusCode)"
    Write-Host "Response: $($response.Content)"
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)"
    Write-Host "Status Code: $($_.Exception.Response.StatusCode.value__)"
}
