function Trans-Files
{

<#

.SYNOPSIS
A PowerShell script that trasfer a files over PowerShell Remoting

.DESCRIPTION
A PowerShell script that trasfer a files over PowerShell Remoting

.PARAMETER LocalFilePath
Local file to transfer

.PARAMETER Target
The remote computer IP or Hostname.

.PARAMETER RemotefilePath
Path for the file you want to transfer on target machine.

.PARAMETER Username
Username to create a PSSession

.PARAMETER Pass
Password to create a PSSession

.EXAMPLE
PS C:\> . .\Trans-Files.ps1
PS C:\> Trans-Files -Localfile .\file.txt -Remotefile "c:\users\admin\desktops\file.txt" -Target 192.168.1.4

.LINK
https://social.technet.microsoft.com/Forums/windows/en-US/17960e2b-bd47-44fd-b25e-c5092940bf40/how-to-pass-a-param-to-script-block-when-using-invokecommand?forum=winserverpowershell

.NOTES
This script has been created for completing the requirements of the SecurityTube PowerShell for Penetration Testers Certification Exam
http://www.securitytube-training.com/online-courses/powershell-for-pentesters/
Student ID: PSP-3250


#>


[CmdletBinding()] Param( 

		[Parameter(Mandatory = $true)]
		[String]
		$LocalFilePath,

		[Parameter(Mandatory = $true)]
		[String]
		$RemotefilePath,

		[Parameter(Mandatory = $true)]
		[String]
		$Target,

        [Parameter(Mandatory = $true)]
        [ValidatePattern({^\w*\\\w*$})]
		[String]
		$Username,

        [Parameter(Mandatory = $true)]
		[String]
		$Pass
		
)

$Password = ConvertTo-SecureString -String $Pass -AsPlainText -Force
$Credential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $Username, $Password
$sess = New-PSSession -ComputerName $Target -Credential $Credential
$Content = Get-Content $LocalFilePath

try {
    $Transfer = Invoke-Command -session $sess -script {param($Contents,$Filepath) $Contents | Out-File "$Filepath"} -Argumentlist $Content,$RemotefilePath
    Write-Host "`n[+] File transferred successfully`n" -ForegroundColor Green
    }

catch {
    Write-Host "`n[-] Something Went Wrong`n" -ForegroundColor Red
}
}
