# Bye-FePhishia
This script pulls the Ice Cube line on phishers and gives users one last chance after clicking a phishing link to say 'Get out of my face!'

Inspired by the talk given by @besimorhino on his Pause-Process tool (https://github.com/besimorhino/Pause-Process) at SANS Blue Team Summit, this was created to give users 'another' chance to detect phishing emails.

## How it works
If a user clicks a link in an email, outlook.exe spawns the child process of iexplore.exe.

This script simply monitors processes, looks for this condition and then pauses the child IE process if it is found.

Once IE is paused, we have as much time as we need to analyze the URL, but we force the user to wait for analysis before they can continue.

Currently, this script just checks Google's SafeBrowsing API to see if there is any info on the URL.  LET'S EXTEND THIS

If the site is not known to be malicious, we show the URL to the user to make sure it is what they think it is.  This is done via parsing the commandline from the process information. The user may then click through the warning and continue accessing the site.

If the site is known to be malicious, inform the user, unpause and kill the process. 

## User Experience

### Unknown Link/Not identified as malicious
![ScreenShot](https://imgur.com/IFGn1DD)
### Malicious/Phishing Link
![ScreenShot](https://imgur.com/lqJSmdz)

### Disclaimer
THIS HAS NOT BEEN TESTED IN A PRODUCTION ENVIRONMENT AND IS MEANT AS A POC ONLY. The author and contributors of this script assume NO liability for the use of this script.
