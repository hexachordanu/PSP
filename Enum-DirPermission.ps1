function Enum-DirPermission{
<#

.SYNOPSIS
Enumerate a directory and find writeable directories for non admin user.


.DESCRIPTION
A poweshell script that enumerate directories inside folders which are writable by non-admin users and print it out for the user.

 
.PARAMTER User
Username whose permission should be check

.PARAMETER Path
The path of the directory to be checked.


.EXAMPLE
PS C:\> . .\Enum-DirPermission.ps1
PS C:\> Enum-DirPermission -Username Anurag


.CREDIT
https://sa1m0nz.wordpress.com/2018/01/26/enumerate-directories-inside-cwindowssystem32-which-are-writable-by-non-admin-users-powershell-for-pentesters-task-3/

.NOTES
This script has been created for completing the requirements of the SecurityTube PowerShell for Penetration Testers Certification Exam
http://www.securitytube-training.com/online-courses/powershell-for-pentesters/
Student ID: PSP-3250
#> 
[CmdletBinding()] Param(
        [Parameter(Mandatory = $true, ValueFromPipeline=$true)]
        [Alias("Username")]
        [String]
        $User,

        [Parameter(Mandatory = $false, ValueFromPipeline=$true)]
        [Alias('Location','Directory')]
        [String]
        $Path = "C:\windows\system32"
        )

$fetchdir = Get-ChildItem $Path | foreach {If ($_.psiscontainer) {$_.fullname}}
$ErrorActionPreference = 'SilentlyContinue'
foreach ($dir in $fetchdir )
    {
    
        $res = icacls $dir
        if ( ($res) -match $User){
            "`n[+] Woaah, Found Some ! `n"
            write-host ( $dir.Split('\')[-1] + "directory maybe writeable for user [ " + $User + " ] in directory - " + $dir) -ForegroundColor Yellow
             " "
            "Confirming the write permission by creating a file.... `n "
            $check = $dir + "\check.txt"
            [io.file]::OpenWrite($check).close()
            Write-Host "[+] Permission Confirmed ! You surely have write permission in: $dir" -foregroundColor Green
            #Deleting the file
            [io.file]::Delete($check)
            }

    }
}
