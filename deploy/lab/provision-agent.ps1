param([string]$Server, [string]$Token)
$msi = "C:\vagrant\hostvigil-agent.msi"
Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn SERVER=$Server TOKEN=$Token" -Wait
& "C:\Program Files\HostVigil\hostvigil-agent.exe" enrol --server $Server --token $Token --ca-fingerprint ""
Start-Service HostVigilAgent
