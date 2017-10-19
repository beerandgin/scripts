#event is the event or indicent number
#hostname is the hostname of the target

$event=$args[0]
$hostname=$args[1]
$dump=dump.raw

write-host $event
Write-Host $hostname

If (!(Test-Path s:))
{
$map = new-object -ComObject WScript.Network
$map.MapNetworkDrive("s:", "\\NASSERVER\SHARE", $true)
}

$path = "S:\investigations\$event"
If(!(test-path $path))
{
New-Item -ItemType Directory -Force -Path $path
}


$path = "S:\investigations\$event\$hostname"
If(!(test-path $path))
{
New-Item -ItemType Directory -Force -Path $path
}

cd $path

c:\Tools\SysinternalsSuite\PsExec64.exe -c -accepteula -nobanner  \\$hostname C:\Tools\winpmem-2.1.post4.exe -o c:\dump.raw  
net use t: /DELETE
net use t:  \\$hostname\c$
cp t:\dump.raw .
rm t:\dump.raw
c:\Tools\Kansa-master\kansa.ps1 -Pushbin -Rmbin -Target $hostname

cd "C:\Program Files\Rekall\"
$arguments = @("pslist", "pstree", "psxview", "netscan", "malfind", "handles", "ldrmodules", "procinfo")
foreach ($argument in $arguments) {.\rekal.exe -f "S:\investigations\$event\$hostname\dump.raw" $argument --output "S:\investigations\$event\$hostname\$argument.txt"}
