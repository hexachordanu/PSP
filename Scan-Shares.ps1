function Scan-Shares
{
<#

.SYNOPSIS
Powershell cmdlet to enumerate all open shares in a network


.DESCRIPTION
A poweshell script that Enumerate all open shares in a network and mark them with read and write access seprately

 
.PARAMTER TargetList
List of ips to scan for open shares


.EXAMPLE
PS C:\> . .\Scan-Shares.ps1
PS C:\> Scan-Shares -TargetList .\list.txt


.CREDIT
https://gallery.technet.microsoft.com/scriptcenter/a231026a-3fdb-4190-9915-38d8cd827348

.NOTES
This script has been created for completing the requirements of the SecurityTube PowerShell for Penetration Testers Certification Exam
http://www.securitytube-training.com/online-courses/powershell-for-pentesters/
Student ID: PSP-3250
#>
[CmdletBinding()] Param(
        [Parameter(Mandatory = $true, ValueFromPipeline=$true)]
        [Alias("IPlist","File","List")]
        [String]
        $Targetlist)


    $Targets = Get-Content $Targetlist
    $ErrorActionPreference = 'SilentlyContinue'
    foreach ($IP in $Targets)
    {
            try{
                #Listing all open shares including ADMIN$ C$ IPC$
                $Shares = get-WmiObject -class Win32_Share -ComputerName $IP
                if ($Shares){ Write-Host "[+] Open Shares of $IP :" -ForegroundColor green }
                foreach ($Share in $Shares.name)
                {
                    Write-Host "   [✔] $Share" -ForegroundColor white
                }

                #listing shares and permission
                $sharesec = Get-WmiObject -Class Win32_LogicalShareSecuritySetting -ComputerName $IP -ea stop
                $sharereport = @() 
                ForEach ($Shares in $sharesec) { 
                    try{
                            
                            #Try to get the security descriptor 
                            $SecurityDescriptor = $ShareS.GetSecurityDescriptor() 
                            #Iterate through each descriptor 
                            ForEach ($DACL in $SecurityDescriptor.Descriptor.DACL) { 
                                
                                $arrshare = New-Object PSObject 
                                $arrshare | Add-Member NoteProperty ShareName $Shares.Name 
                                $arrshare | Add-Member NoteProperty "  Group  " $DACL.Trustee.Name 
                                #Convert the current output into something more readable 
                                Switch ($DACL.AccessMask) { 
                                    2032127 {$AccessMask = "FullControl"} 
                                    1179785 {$AccessMask = "Read"} 
                                    1180063 {$AccessMask = "Read, Write"} 
                                    1179817 {$AccessMask = "ReadAndExecute"} 
                                    -1610612736 {$AccessMask = "ReadAndExecuteExtended"} 
                                    1245631 {$AccessMask = "ReadAndExecute, Modify, Write"} 
                                    1180095 {$AccessMask = "ReadAndExecute, Write"} 
                                    268435456 {$AccessMask = "FullControl (Sub Only)"} 
                                    default {$AccessMask = $DACL.AccessMask} 
                                    } 
                                $arrshare | Add-Member NoteProperty AccessMask $AccessMask 
                                #Convert the current output into something more readable 
                                Switch ($DACL.AceType) { 
                                    0 {$AceType = "Allow"} 
                                    1 {$AceType = "Deny"} 
                                    2 {$AceType = "Audit"} 
                                    } 
                                #$arrshare | Add-Member NoteProperty AceType $AceType 
                                #Add to existing array 
                                $sharereport += $arrshare 
                               }
                          }
                          catch
                          { 
                             Write-host "Unable to list $Shares"  -ForegroundColor red
                          }
                }
                   
                    # Marking shares permission seprately 
                    $sharereport | Out-String | Write-Host -ForegroundColor Green
                    #$sharereport | Where-Object {$_.AccessMask -eq "Read, Write"} | Out-String | Write-Host -ForegroundColor Green
                    #$sharereport | Where-Object {$_.AccessMask -eq "ReadAndExecute"} | Out-String | Write-Host -ForegroundColor Green
                    #$sharereport | Where-Object {$_.AccessMask -ne "FullControl" -and $_.AccessMask -ne "ReadAndExecute" -and $_.AccessMask -ne "Read, Write"} | Out-String | Write-Host -ForegroundColor Green
                   
                    
           
           
     }
     catch{
      Write-host "[-] Could not connect to the target - "$IP  -ForegroundColor red
      }
    }
}
