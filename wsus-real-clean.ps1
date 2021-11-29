# Meant to run on the WSUS server itself.
# Run as admin, and run Server Cleanup from WSUS Manager Options afterwards to delete the "mark for deletion" files.
# It is declining everything for Windows builds 1803 and before as those should not be used anyway.
# Also removing en-GB versions as -my personal needs- only need the en-US versions.

$Computer = $env:COMPUTERNAME
$Domain = $env:USERDNSDOMAIN
$FQDN = "$Computer" + "." + "$Domain"
[String]$updateServer1 = $FQDN
[Boolean]$useSecureConnection = $False
[Int32]$portNumber = 8530

# Load .NET assembly

[void][reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")

$count = 0

# Connect to WSUS Server

$updateServer = [Microsoft.UpdateServices.Administration.AdminProxy]::getUpdateServer($updateServer1,$useSecureConnection,$portNumber)

write-host "<<<Connected sucessfully >>>" -foregroundcolor "yellow"

$updatescope = New-Object Microsoft.UpdateServices.Administration.UpdateScope

$u=$updateServer.GetUpdates($updatescope )

foreach ($u1 in $u )

{

if ($u1.IsSuperseded -eq 'True' -Or $u1.Title -like '*Itanium*' -Or $u1.Title -like '*ARM64*' -Or $u1.Title -like '*en-gb*' -Or $u1.Title -like '*Version 1511*' -Or $u1.Title -like '*Version 1607*' -Or $u1.Title -like '*Version 1703*' -Or $u1.Title -like '*Version 1709*' -Or $u1.Title -like '*Version 1803*')

{

write-host Decline Update : $u1.Title

$u1.Decline()

$count=$count + 1

}

}

write-host Total Declined Updates: $count

trap

{

write-host "Error Occurred"

write-host "Exception Message: "

write-host $_.Exception.Message

write-host $_.Exception.StackTrace

exit

}

[reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")
$wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer();
$declined=$wsus.GetUpdates() | Where {$_.IsDeclined -eq $true}
$declined| ForEach-Object {$wsus.DeleteUpdate($_.Id.UpdateId.ToString()); Write-Host $_.Title removed }

# EOF
