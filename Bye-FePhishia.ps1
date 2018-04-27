<#
Author: Josh Johnson
version 0.1 - 4/27/18

Inspired by the talk given by Mick Douglas on Pause-Process at SANS Blue Team Summit, this was created to give users 'another' chance to detect phishing emails.

If a user clicks a link in an email, outlook.exe spawns the child process of iexplore.exe.

This script simply monitors processes, looks for this condition and then pauses the child IE process if it is found.

Once IE is paused, we have as much time as we need to analyze the URL, but we force the user to wait for analysis before they can continue.

Currently, this script just checks Google's SafeBrowsing API to see if there is any info on the URL.  LET'S EXTEND THIS

If the site is not known to be malicious, we show the URL to the user to make sure it is what they think it is.  This is done via parsing the commandline from the process information. The user may then click through the warning and continue accessing the site.

If the site is known to be malicious, inform the user, unpause and kill the process. 

THIS HAS NOT BEEN TESTED IN A PRODUCTION ENVIRONMENT AND IS MEANT AS A POC ONLY. The author and contributors of this script assume NO liability for the use of this script.

#>
IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/besimorhino/Pause-Process/master/pause-process.ps1")
#Or download this locally and import it - PS. Mick did the hard work here - check out his project at https://github.com/besimorhino/Pause-Process
#Import-Module C:\scripts\Pause-Process.ps1 

$safebrowsing = "ON"
$safebrowsingKey = "SafeBrowsing key here"

#Extend on this - use more sources like Whois (registration date < 30 days = deny), Virustotal, threat feeds, etc.
Function getSafeBrowsingResult($url){
    $retRes = 0
    $urlToPOST = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + $safebrowsingKey
    $postBody = '{"client":{"clientId":"JJ","clientVersion":"1.5.2"},"threatInfo":{"threatTypes":["MALWARE","SOCIAL_ENGINEERING"],"platformTypes":["WINDOWS"],"threatEntryTypes":["URL"],"threatEntries":[{"url":"'+$url+'"}]}}'
    $results = Invoke-WebRequest -Uri $urlToPOST -Method POST -ContentType "application/json" -Body $postBody -UseBasicParsing
    $content = $results.Content | ConvertFrom-Json

    if($content.matches){ #We have bad results
        $retRes = 1
    }
    $retRes
}

$acceptedProcs = @()
$exit = 0
While($exit -eq 0){
    Get-WmiObject Win32_Process |Where-Object {$_.ProcessName -eq "iexplore.exe"} |Select-Object ProcessID,ParentProcessID | ForEach-Object { #for each IE process
        $parentid = $_.ParentProcessID
        $processid = $_.ProcessID
        #Check the parent and see if it is Outlook and something new
        if(Get-WmiObject Win32_Process | Where-Object {($_.ProcessID -eq $parentid -and $_.ProcessName -eq "outlook.exe" -and $acceptedProcs -notcontains $processid)}){ 
            $retRes = 0
            $malicious = 0
            #Pause the process
            Pause-Process -Id $processid
               
            write-host -foregroundcolor red "Found OUTLOOK PARENT PROCESS for IExplore.exe - pausing process - $processid - and alerting user"          
            #Parse out the URL that the user is accessing
            $IE = Get-WmiObject Win32_Process | Where-Object {($_.ProcessID -eq $processid)}
            $splitMsg = $IE.Commandline -split "`" "
            $url = $splitMsg[1]

            Add-Type -AssemblyName System.Windows.Forms | Out-Null
            if($safebrowsing -eq "ON"){ #Check Safebrowsing API for this URL
               $retRes = getSafeBrowsingResult $url           
            }
            if($retRes -eq 1){
                $Title = "ALERT - Malicious Link Clicked"
                $Message = "Sorry, this site has been classified as malicious.  The web browser will now close. Please delete the email containing this link:`n $url "
                $malicious = 1
            }
            else{
                $Title = "CAUTION - Link Clicked"
                $Message = "You clicked a link in an email, dummy! Are you sure you want to browse to $url ?"
            }
            
            $MsgBox = [System.Windows.Forms.MessageBox]

            if($malicious -eq 1 -or $Decision -eq "Cancel"){
                $Decision = $MsgBox::Show($Message,$Title)
                Unpause-Process -Id $processid 
                Get-Process -Id $processid | Stop-Process
                Write-Host -ForegroundColor Green "Killed malicious URL in Process ID $processid"
            }
            else{
                $Decision = $MsgBox::Show($Message,$Title,"OkCancel", "Information")
                If ($Decision -eq "Ok") {
                    Write-Host -ForegroundColor Yellow "User accepted access to $url. Allowing access"
                    $acceptedProcs += $processid
                    UnPause-Process -id $processid
                }
            }
        }
    }
}
