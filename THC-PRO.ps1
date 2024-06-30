 
#Enable this script only: powershell.exe -noprofile -executionpolicy bypass -file .\THC-PRO.ps1
#(go down to execution line)
#for quicker testing: 
    #Get status: Get-ExecutionPolicy
    #Set status unrestricted/remotesigned: Set-ExecutionPolicy RemoteSigned
    #Set status back to restricted: Set-ExecutionPolicy Res
##Good quick info, implement later for hunters  https://mahim-firoj.medium.com/incident-response-and-threat-hunting-using-deepbluecli-tool-bf5d4c52c8a8

# VARIABLES - BANNERS

$Banner1of4= @"
_________________________________________________________________________________
"@ 
$Banner2of4= @"
  ________  ______  _________  ______   __  ____  ___   __________________  _____
 /_  __/ / / / __ \/ ____/   |/_  __/  / / / / / / / | / /_  __/ ____/ __ \/ ___/
  / / / /_/ / /_/ / __/ / /| | / /    / /_/ / / / /  |/ / / / / __/ / /_/ /\__ \ 
 / / / __  / _, _/ /___/ ___ |/ /    / __  / /_/ / /|  / / / / /___/ _, _/___/ / 
/_/ /_/ /_/_/_|_/_____/_/  |_/_/   _/_/_/_/\____/_/_|_/_/_/_/_____/_/ |_|/____/  
          / ____/ __ \/ /   / /   / ____/ ____/_  __/  _/ __ \/ | / /            
         / /   / / / / /   / /   / __/ / /     / /  / // / / /  |/ /             
        / /___/ /_/ / /___/ /___/ /___/ /___  / / _/ // /_/ / /|  /              
        \____/\____/_____/_____/_____/\____/ /_/ /___/\____/_/ |_/ PRO`n
"@   
$Banner3of4= @"
                                            Catalyzed with purpose by: Adam Kim
"@   

$Banner4of4= @"
_________________________________________________________________________________`n
"@   

$HealthCheck = "False"

# VARIABLES - ParentFolder
$ParentFolder = "Threat Hunters Collection"
$UserProfilePath = $($env:userprofile)
$UserDesktopPath = [Environment]::GetFolderPath("Desktop")
$StatusLoadingLineBreak = "`n`n`n`n`n`n"
$StatusBlankSpace = "                   "
$StatusCreatedParentFolder = "> [ Adding new directory $UserDesktopPath\$ParentFolder ]`n"
$StatusChangedDirToParentFolder = ">> [ Changed directory to $UserDesktopPath\$ParentFolder ]`n"
$StatusWipeReminder = "[ Don't forget to wipe THC :) ]"

# VARIABLES A - AppA (Host Info)
$BannerA = @"
_________________________________________________________________________________
                    __  ______  ___________   _____   ____________ 
                   / / / / __ \/ ___/_  __/  /  _/ | / / ____/ __ \
                  / /_/ / / / /\__ \ / /     / //  |/ / /_  / / / /
                 / __  / /_/ /___/ // /    _/ // /|  / __/ / /_/ / 
                /_/ /_/\____//____//_/    /___/_/ |_/_/    \____/   
_________________________________________________________________________________`n
"@
    $AppAName = "Host Info"
    $AppADescription = "Enumerate Host Info"
    $Hostname = hostname
    $PrintWorkingDirectory = Get-Location
        #Grab IP info
        $IPAddress= $env:HostIP = (Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"}).IPv4Address.IPAddress
    $GetVolume = "Get-Volume | Select-Object @{Name='Drive';Expression='DriveLetter'}, FileSystemLabel, @{Name='Free `(GB`)';Expression={[math]::Round(`$_.SizeRemaining / 1GB, 2)}}, @{Name='Size `(GB`)';Expression={[math]::Round(`$_.Size / 1GB, 2)}}, @{Name='Type';Expression='FileSystemType'}, @{Name='Mount';Expression='DriveType'}, @{Name='Health';Expression='HealthStatus'},@{Name='Status';Expression='OperationalStatus'}| Format-Table -Wrap | Out-String"
    $GetCIM = "Get-CimInstance -ClassName Win32_Desktop | Select-Object @{Name='Name | ScreenSaver ------->';Expression='Name'}, @{Name='Active';Expression='ScreenSaverActive'}, @{Name='Secure';Expression='ScreenSaverSecure'}, @{Name='Timeout';Expression='ScreenSaverTimeout'}| Format-Table -Wrap | Out-String"
    $StatusAExportComplete = "`n>>>>>>>>>>> [ Exported raw logs to $UserDesktopPath\$ParentFolder\$Hostname-Host-Info ]`n"

# FUNCTION A
    function HostInfo {
    #Clear
    Clear
    
    #Make room for Loadingbar
    Write-Host $StatusLoadingLineBreak
    
    # Start transcript to capture all output, appends info if tracking changes.
    Start-Transcript -Path "$UserDesktopPath\$ParentFolder\$Hostname-Host-Info.txt" -Append | Out-Null
    
    # Welcome BannerAppA
    Write-Host $BannerA
    
    # Host Information
    Write-Host "----------------------------------- [ HOST INFORMATION ] -----------------------------------`n" -ForegroundColor Green

    # Get current time stamp
    Write-Host "[Date]: $(Get-Date)"
    
    # Notify hostname & IP address
    Write-Host "[Hostname]: $Hostname"
    Write-Host "[Profile]: $UserProfilePath"
    Write-Host "[Desktop Path]: $UserDesktopPath"
    Write-Host "[IP Address]: $IPAddress" -NoNewline
    
    # More PC Info
    Get-ComputerInfo -Property "CsNetworkAdapters","CsDomain","CsUserName","LogonServer","WindowsRegisteredOwner","WindowsProductName","WindowsEditionId","OsArchitecture","OsBuildNumber","OsVersion","CsManufacturer","CsModel","BiosName","CsProcessors","CsNumberOfLogicalProcessors","TimeZone","OsInstallDate","OsLastBootUpTime","OsLocalDateTime","OsUptime"

    # Drive Information
    Write-Host "---------------------------------- [ DRIVE INFORMATION ] ------------------------------------" -ForegroundColor Green
    Invoke-Expression $GetVolume.Trim()

    # All Desktops in Use or Not
    Write-Host "-------------------------------- [ DESKTOPS | SCREENSAVER ] ---------------------------------" -ForegroundColor Green
    Invoke-Expression $GetCIM.Trim()
    
    Write-Host $StatusAExportComplete -ForegroundColor Yellow
    # Stop transcript
    Stop-Transcript | Out-Null
    pause
}

# VARIABLES B - AppB (Sysmon)
$BannerB = @"
_________________________________________________________________________________
                       _______  _______ __  _______  _   __
                      / ___/\ \/ / ___//  |/  / __ \/ | / /
                      \__ \  \  /\__ \/ /|_/ / / / /  |/ / 
                     ___/ /  / /___/ / /  / / /_/ / /|  /  
                    /____/  /_//____/_/  /_/\____/_/ |_/
_________________________________________________________________________________`n
"@
    $AppBName = "Sysmon"
    $AppBDescription = "logs system activity to the Windows event log"
    $AppBVersion = "xx.xx"
    $AppBFolder = "$AppBName"

# VARIABLES C - AppC (DeepBlueCLI)
$BannerC = @"
_________________________________________________________________________________
        ____  ________________     ____  __    __  ________   ________    ____
       / __ \/ ____/ ____/ __ \   / __ )/ /   / / / / ____/  / ____/ /   /  _/
      / / / / __/ / __/ / /_/ /  / __  / /   / / / / __/    / /   / /    / /  
     / /_/ / /___/ /___/ ____/  / /_/ / /___/ /_/ / /___   / /___/ /____/ /   
    /_____/_____/_____/_/      /_____/_____/\____/_____/   \____/_____/___/
_________________________________________________________________________________`n
"@
    $AppCName = "DeepBlueCLI"
    $AppCDescription = "Hunt via Windows Event Logs"
    $AppCFolder = "DeepBlueCLI"
        # URLs
        $AppCURLMain = "https://github.com/sans-blue-team/DeepBlueCLI/archive/refs/heads/master.zip"
        $AppCURLMirror = "https://github.com/resv/THC-MIRROR-APPS/raw/main/DeepBlueCLI-master.zip"
           
    $AppCHashMain = "2295C0E92697A8F5425F20E4119F7A049428C2A47AF48F88ABABA206309DEE51"
    $AppCHashMirror = "A86D97A25D790F860B89887C241961C60BBCD12C13D47C31FA4125CBF30E8C1E"

    # VARIABLES C - Status notifications
    $StatusCCreatedAppCFolder = "> [ Adding directory $UserDesktopPath\$ParentFolder\$AppCFolder ]`n"
    $StatusCChangedDirToAppCFolder = ">> [ Changed directory to ..\$AppCFolder ]`n"
    $StatusCCheckAndRemoveExisting = ">>> [ Removing any existing DeepBlue files ]`n"
    $StatusCDownloadApp = ">>>> [ Downloading `"$AppCName`" ]`n"
    $StatusCHashCheck = ">>>>> [ Checking hash ]`n"
    $StatusCExtractedApp = ">>>>>> [ Extracted `"$AppCName`" ]`n"
    $StatusCRemoveDownload =  ">>>>>>> [ Removed downloaded files for `"$AppCName`" ]`n"
    $StatusCChangedDirToAppFolder = ">>>>>>>> [ You are in the $UserDesktopPath\$ParentFolder\$AppCFolder ]`n"
    $StatusCReady = ">>>>>>>>> [ Ready for Hunting... ]`n"
    $StatusCLoading = ">>>>>>>>>> [ Retrieving Data... ]`n"
    $StatusCCreatedAppCLogFolder = "`n>>>>>>>>> [ Adding new directory `"$Hostname-Evtx-Logs`" ]`n"
    $StatusCCreatedAppCImportLogFolder = "`n>>>>>>>> [ Adding new directories $UserDesktopPath\$ParentFolder\Import-Log-Folder ]`n"
    $StatusCExportComplete = "`n>>>>>>>>>>> [ Exported raw logs to $UserDesktopPath\$ParentFolder\$Hostname-Evtx-Logs ]`n"
    $DeepBlueExecute = ".\DeepBlue.ps1"
    $LogPathExportFolder = "$UserDesktopPath\$ParentFolder\$Hostname-Evtx-Logs"
    $LogPathImportFolder = "$UserDesktopPath\$ParentFolder\Import-Log-Folder"
    $LogPathSecurity = "C:\Windows\System32\winevt\Logs\Security.evtx"
    $LogPathSystem = "C:\Windows\System32\winevt\Logs\System.evtx"
    $LogPathApplication = "C:\Windows\System32\winevt\Logs\Application.evtx"
    $LogPathAppLocker = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-AppLocker%4EXE and DLL.evtx"
    $LogPathPowerShell = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx"
    $LogPathSysmon = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx"
    $LogPathWMI = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-WMI-Activity%4Operational.evtx"
    $LogPathImportSecurity = "$UserDesktopPath\$ParentFolder\Import-Log-Folder\Security.evtx"
    $LogPathImportSystem = "$UserDesktopPath\$ParentFolder\Import-Log-Folder\System.evtx"
    $LogPathImportApplication = "$UserDesktopPath\$ParentFolder\Import-Log-Folder\Application.evtx"
    $LogPathImportAppLocker = "$UserDesktopPath\$ParentFolder\Import-Log-Folder\Microsoft-Windows-AppLocker%4EXE and DLL.evtx"
    $LogPathImportPowerShell = "$UserDesktopPath\$ParentFolder\Import-Log-Folder\Microsoft-Windows-PowerShell%4Operational.evtx"
    $LogPathImportSysmon = "$UserDesktopPath\$ParentFolder\Import-Log-Folder\Microsoft-Windows-Sysmon%4Operational.evtx"
    $LogPathImportWMI = "$UserDesktopPath\$ParentFolder\Import-Log-Folder\Microsoft-Windows-WMI-Activity%4Operational.evtx"
    $PipeList = "|Format-List"
    $PipeTable = "|Format-Table"
    $PipeGrid = "|Out-GridView"
    $PipeHtml = "|ConvertTo-Html"
    $PipeJson = "|ConvertTo-Json"
    $PipeXml = "|ConvertTo-Xml"

    # AppCMenuImport
    $AppCMenuImportSub = @"
    `n
    $global:LogTarget
     ______[ IMPORT SUB MENU ]_______
    |                                |
    | *[List]  | Format-List view    |
    | *[Table] | Format-Table view   |
    | *[Grid]  | Out-GridView view   |
    |  [HTML]  | ConvertTo-Html view |
    |  [JSON]  | ConvertTo-Json view |
    |  [XML]   | ConvertTo-Xml view  |
    |  [Records]| Get $global:LogTarget Count (This can take a long time)  |
    |  [Help]  |  Syntax & Paths     |
    |  [Back]  | Back to Main Menu   |
    |________________________________|`n `n
"@    

    # AppCMenuMain
    $AppCMenuImportMain = @"
    `n
     _______[ IMPORT MAIN MENU ]________
    |                                   |
    | [Security]    | $($global:LogCountImportSecurity.Count) Records
    | [System]      | $($global:LogCountImportSystem.Count) Records
    | [Application] | $($global:LogCountImportApplication.Count) Records
    | [AppLocker]   | $($global:LogCountImportAppLocker.Count) Records
    | [Powershell]  | $($global:LogCountImportPowershell.Count) Records
    | [Sysmon]      | $($global:LogCountImportSysmon.Count) Records
    | [WMI]         | $($global:LogCountImportWMI.Count) Records
    | [All]         | Filters all logs  |
    | [Help]        | Syntax & Paths    |
    | [Back]        | Back to Main Menu |
    |___________________________________|`n `n
"@

    # AppCMenuSub
    $AppCMenuSub = @"
    `n
           $global:LogTarget ($LogCount)
     _______[ DEEPBLUECLI SUB MENU ]______
    |                                     |
    | *[List]      | Format-List view     |
    | *[Table]     | Format-Table view    |
    | *[Grid]      | Out-GridView view    |
    |  [HTML]      | ConvertTo-Html view  |
    |  [JSON]      | ConvertTo-Json view  |
    |  [XML]       | ConvertTo-Xml view   |
    |  [Help]      | Syntax & Paths       |
    |  [Export]    | Export Logs          |
    |  [Exit]      | Hard Exit            |
    |  [Back]      | Back to Main Menu    |
    |_____________________________________|`n `n
"@

    # AppCMenuMain
    $AppCMenuMain = @"
    `n
     _____[ DEEPBLUECLI MAIN MENU ]_____
    |                                   |
    | [Security]    | $LogCountSecurity Records
    | [System]      | $LogCountSystem Records
    | [Application] | $LogCountApplication Records
    | [AppLocker]   | $LogCountAppLocker Records
    | [Powershell]  | $LogCountPowerShell Records
    | [Sysmon]      | $LogCountSysmon Records
    | [WMI]         | $LogCountWMI Records
    | [All]         | Filters all logs  |
    | [Import]      | Import Logs & Run |
    | [Export]      | Export all logs   |
    | [Help]        | Syntax & Paths    |
    | [Wipe]        | Wipe DeepBlueCLI  |
    | [Exit]        | Hard Exit         |
    | [Back]        | Back to Main Menu |
    |___________________________________|`n `n
"@

    $DBCLIHelp = @"
`n
 __________________________________________________[ SYNTAX ]__________________________________________________
|                                                                                                              |
| [  <SCRIPT> ----- <HOST LOG PATH> --------------------------------------------------------- | <SWITCH> -- ]  |
| [ .\DeepBlue.ps1 C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx | Format-List ]  |
|______________________________________________________________________________________________________________|

         ______________________________________[ HOST LOG PATHS ]_______________________________________ 
        |                                                                                               |
        | [Security] "C:\Windows\System32\winevt\Logs\Security.evtx"                                    |
        | [System] "C:\Windows\System32\winevt\Logs\System.evtx"                                        |
        | [Application] "C:\Windows\System32\winevt\Logs\Application.evtx"                              |
        | [AppLocker] "C:\Windows\System32\winevt\Logs\Microsoft-Windows-AppLocker%4EXE and DLL.evtx"   |
        | [PowerShell] "C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx" |
        | [Sysmon] "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx"         |
        | [WMI] "C:\Windows\System32\winevt\Logs\Microsoft-Windows-WMI-Activity%4Operational.evtx"      |
        |_______________________________________________________________________________________________|

                                     ___________[ SWITCHES ]___________
                                    |                                  |
                                    | *[List]  "| Format-List view"    |
                                    | *[Table] "| Format-Table view"   |
                                    | *[Grid]  "| Out-GridView view"   |
                                    |  [HTML]  "| ConvertTo-Html view" |
                                    |  [JSON]  "| ConvertTo-Json view" |
                                    |  [XML]   "| ConvertTo-Xml view"  |
                                    |__________________________________|

                  __________________________[ IMPORTED LOG PATHS ]__________________________
                 |                                                                          |
                 | [Imported Logs] "..\Desktop\Threat Hunters Collection\Import-Log-Folder" |
                 |__________________________________________________________________________|

                 ___________________________[ EXPORTED LOG PATHS ]____________________________
                |                                                                             |
                | [Exported Logs] "..\Desktop\Threat Hunters Collection\"Hostname"-Evtx-Logs" |
                |_____________________________________________________________________________|
`n
"@

# Stores Record Count in variable to use and display on the AppC Menu Main
function RunRecordCount {
    $global:LogCountSecurity = Invoke-expression "get-winevent -listlog Security | Select-Object -ExpandProperty RecordCount"
    $global:LogCountSystem = Invoke-expression "get-winevent -listlog System | Select-Object -ExpandProperty RecordCount"
    $global:LogCountApplication = Invoke-expression "get-winevent -listlog Application | Select-Object -ExpandProperty RecordCount"
    $global:LogCountAppLocker = Invoke-expression "get-winevent -listlog `"Microsoft-Windows-AppLocker/EXE and DLL`" | Select-Object -ExpandProperty RecordCount"
    $global:LogCountPowerShell = Invoke-expression "get-winevent -listlog `"Windows PowerShell`" | Select-Object -ExpandProperty RecordCount"
    $global:LogCountSysmon = Invoke-expression "get-winevent -listlog `"Microsoft-Windows-Sysmon/Operational`" | Select-Object -ExpandProperty RecordCount"
    $global:LogCountWMI = Invoke-expression "get-winevent -listlog `"Microsoft-Windows-WMI-Activity/Operational`" | Select-Object -ExpandProperty RecordCount"

}
# Running record count on imported files take way too long, this is disabled for now
function RunImportRecordCount($LogTarget){

    clear
    Write-Host "`n>>>>>>>>> [ Reboot THC if you want to exit out of this process, it can take a long time...]`n"
    Write-Host ">>>>>>>>>> [ Counting records in $LogTarget log ]`n"
    
    if ($LogTarget -eq "Imported Security"){
    $global:LogCountImportSecurity = Invoke-expression "get-winevent -Path `"$UserDesktopPath\$ParentFolder\Import-Log-Folder\Security.evtx`" -MaxEvents 1000000"
    $ImportRecordCount = $global:LogCountImportSecurity.Count
    }

    if ($LogTarget -eq "Imported System"){
    $global:LogCountImportSystem = Invoke-expression "get-winevent -Path `"$UserDesktopPath\$ParentFolder\Import-Log-Folder\System.evtx`" -MaxEvents 1000000"
    $ImportRecordCount = $global:LogCountImportSystem.Count
    }

    Write-Host ">>>>>>>>>>> [ $LogTarget has ($ImportRecordCount) records ]`n"
}

# Import Folder creation, wait for import confirmation from user, then run
function RunImport{
    # Clear
    clear

    # Welcome BannerAppC
    Write-Host $BannerC
    
    # Create export log directory and notify path
    $null = new-item -path "$UserDesktopPath\$ParentFolder" -name "Import-Log-Folder" -itemtype directory -Force
    Write-Host $StatusCCreatedAppCImportLogFolder
    Write-Host ">>>>>>>>> [ DeepBlue will assume unchanged default evtx file names ] `n"
    Write-Host ">>>>>>>>>> [ DROP EXTERNAL EVTX FILES TO `"Import-Log-Folder`", DO NOT CHANGE FILENAMES ]`n`n`n" -ForegroundColor Yellow
    Write-Host "                                       Press enter to continue...                                       `n`n" -ForegroundColor Yellow
    
    # Give user time to import file to the import folder, wait for the user to press Enter
    Read-Host
    # Notify user that this will take a long time..and it will..These global variables can be commented to remove this wait time but you won't get the record count.
    Write-Host "                            Checking record count, this can take a long time...                                       " -ForegroundColor Yellow

    # This part does the record count for Import Menu
    $global:LogCountImportSecurity = Invoke-expression "get-winevent -Path `"$LogPathImportSecurity`" -MaxEvents 500000"
    #$global:LogCountImportSystem = Invoke-expression "get-winevent -Path `"$UserDesktopPath\$ParentFolder\Import-Log-Folder\System.evtx`" -MaxEvents 500000"
    #$global:LogCountImportApplication = Invoke-expression "get-winevent -Path `"$UserDesktopPath\$ParentFolder\Import-Log-Folder\Application.evtx`" -MaxEvents 500000"
    $global:LogCountImportAppLocker = Invoke-expression "get-winevent -Path `"$LogPathImportAppLocker`" -MaxEvents 500000"
    #$global:LogCountImportPowerShell = Invoke-expression "get-winevent -Path `"$UserDesktopPath\$ParentFolder\Import-Log-Folder\Microsoft-Windows-PowerShell%4Operational.evtx`" -MaxEvents 500000"
    #$global:LogCountImportSysmon = Invoke-expression "get-winevent -Path `"$UserDesktopPath\$ParentFolder\Import-Log-Folder\Microsoft-Windows-Sysmon%4Operational.evtx`" -MaxEvents 500000"
    #$global:LogCountImportWMI = Invoke-expression "get-winevent -Path `"$UserDesktopPath\$ParentFolder\Import-Log-Folder\Microsoft-Windows-WMI-Activity%4Operational.evtx`" -MaxEvents 500000"

    do
    {
        $selectionImport = Read-Host $AppCMenuImportMain "Imported main menu, Waiting for your input"
        switch ($selectionImport)
        {
            'Security' {
                clear
                Write-Host $BannerC
                $global:LogTarget = "Imported Security"
                $global:LogType = $LogPathImportSecurity
                $selection2Import = Read-Host $AppCMenuImportSub "$global:LogTarget log sub menu, waiting for your input"
                switch ($selection2Import)
                {
                    'List' {
                        $global:LogFormat = $PipeList
                        RunDeepBlue
                        } 
                    'table' {
                        $global:LogFormat = $PipeTable
                        RunDeepBlue
                        }
                    'Grid' {
                        $global:LogFormat = $PipeGrid
                        RunDeepBlueImported
                        } 
                    'Html' {
                        $global:LogFormat = $PipeHtml
                        RunDeepBlueImported
                        } 
                    'Json' {
                        $global:LogFormat = $PipeJson
                        RunDeepBlueImported
                        } 
                    'Xml' {
                        $global:LogFormat = $PipeXml
                        RunDeepBlueImported
                        }
                    'Records'{
                        $selection3Import = Read-Host "Check the imported evtx exists under the default filename, This can take a long time, are you sure you want to continue? (Y/N)"
                        switch ($selection3Import)
                        {
                            'Y'{RunImportRecordCount($LogTarget)} 
                            'N'{AppCMenuImportMain}
                        }
                    }
                    'Help' {
                        Clear-Host
                        Write-Host $BannerC
                        Write-Host $DBCLIHelp      
                        }        
                    'Back' {
                        AppCMenuImportMain
                        } 
                }
                pause
            }
            'System' {
                clear
                Write-Host $BannerC
                $global:LogTarget = "Imported System"
                $global:LogType = $LogPathImportSystem
                $selection2Import = Read-Host $AppCMenuImportSub "$global:LogTarget log sub menu, waiting for your input"
                switch ($selection2Import)
                {
                    'List' {
                        $global:LogFormat = $PipeList
                        RunDeepBlue
                        } 
                    'table' {
                        $global:LogFormat = $PipeTable
                        RunDeepBlue
                        }
                    'Grid' {
                        $global:LogFormat = $PipeGrid
                        RunDeepBlueImported
                        } 
                    'Html' {
                        $global:LogFormat = $PipeHtml
                        RunDeepBlueImported
                        } 
                    'Json' {
                        $global:LogFormat = $PipeJson
                        RunDeepBlueImported
                        } 
                    'Xml' {
                        $global:LogFormat = $PipeXml
                        RunDeepBlueImported
                        }
                    'Records'{
                        $selection3Import = Read-Host "Check the imported evtx exists under the default filename, This can take a long time, are you sure you want to continue? (Y/N)"
                        switch ($selection3Import)
                        {
                            'Y'{RunImportRecordCount($LogTarget)} 
                            'N'{AppCMenuImportMain}
                        }
                    }
                    'Help' {
                        Clear-Host
                        Write-Host $BannerC
                        Write-Host $DBCLIHelp      
                        }        
                    'Back' {
                        AppCMenuImportMain
                        } 
                }
                pause
            }
            'Application' {
            #Applicationflow
            } 
            'AppLocker' {
            #Applockerflow
            } 
            'PowerShell' {
                #Powershellflow
            } 
            'Sysmon' {
            #Sysmonflow
            } 
            'WMI' {
            #WMI flow
            }
            'Help' {
                Clear-Host
                Write-Host $BannerC
                Write-Host $DBCLIHelp     
            } 
            'Back' {
            DBCLIMenuMain
            }
        }
        pause
    }
    until ($selection -eq 'q')
}

# Exporting DeepBlue logs will use this switchcase
function ExportLog($LogType){
    # Clear
    clear

    # Welcome BannerAppC
    Write-Host $BannerC

    # Create export log directory and notify path
    function global:CreateLogFolder{
        $null = new-item -path "$UserDesktopPath\$ParentFolder" -name "$Hostname-Evtx-Logs" -itemtype directory -Force
        Write-Host $StatusCCreatedAppCLogFolder -ForegroundColor Yellow
        }
    CreateLogFolder

    # Notify export status
    foreach ($Type in $LogType){
        Write-Host ">>>>>>>>> [ Exporting $Type Log ]"
    }
    
    switch ($LogType){
        'Security' {Copy-Item -Path $LogPathSecurity -Destination "$LogPathExportFolder"}
        'System' {Copy-Item -Path $LogPathSystem -Destination "$LogPathExportFolder"}
        'Application' {Copy-Item -Path $LogPathApplication -Destination "$LogPathExportFolder"}
        'AppLocker' {Copy-Item -Path $LogPathAppLocker -Destination "$LogPathExportFolder"}
        'PowerShell' {Copy-Item -Path $LogPathPowerShell -Destination "$LogPathExportFolder"}
        'Sysmon' {Copy-Item -Path $LogPathSysmon -Destination "$LogPathExportFolder"}
        'WMI' {Copy-Item -Path $LogPathWMI -Destination "$LogPathExportFolder"}
    }
    # Notify user that the export is complete
    Write-host $StatusCExportComplete -ForegroundColor Yellow
}

# DeepBlue Function is called from the DBCLI Submenu grabbing the logtype and logformat requested by the user
function RunDeepBlue{
    # Clear
    clear

    # Welcome BannerAppC
    Write-Host $BannerC
    
    # Switch reading what the LogTarget is then getting the explicit LogCount
    switch ($LogTarget) {
        "Security"     { $LogCount = $LogCountSecurity }
        "System"       { $LogCount = $LogCountSystem }
        "Application"  { $LogCount = $LogCountApplication }
        "AppLocker"    { $LogCount = $LogCountApplocker }
        "PowerShell"   { $LogCount = $LogCountPowerShell }
        "Sysmon"       { $LogCount = $LogCountSysmon }
        "WMI"          { $LogCount = $LogCountWMI }
        "Imported Security"     { $LogCount = $LogCountImportSecurity }
        "Imported System"       { $LogCount = $LogCountImportSystem }
        "Imported Application"  { $LogCount = $LogCountImportApplication }
        "Imported AppLocker"    { $LogCount = $LogCountImportApplocker }
        "Imported PowerShell"   { $LogCount = $LogCountImportPowerShell }
        "Imported Sysmon"       { $LogCount = $LogCountImportSysmon }
        "Imported WMI"          { $LogCount = $LogCountImportWMI }
    }

    # Notify the query is running
    Write-Host ">>>>>>>> [ Hunting Through $LogCount $LogTarget Records ]"
    
    # Store DeepBlue explicit request so we can check use this to check for blank results with the if statement
    $output = Invoke-expression ".\DeepBlue.ps1 $LogType $LogFormat"

    # Check if the results are is empty and notify user if so.
    if (-not $output) {
    Write-Host "`n>>>>>>>>> [ No Flagged Results... ]`n`n"
    } else {
    # Output the table or do whatever you need with the results
    $output
    }
}

# AppC (DBCLI) Main Menu
function DBCLIMenuMain{
    if ($HealthCheck -eq "True") 
    {   
        #place holder for another command
        do
        {
            # Executes function to grab record count to populate AppCMenuMain
            RunRecordCount
            # MainMenu for DBCLI, not case sensitive, will take alphanumeric inputs
            $selection = Read-Host $StatusCReady $BannerC $AppCMenuMain "DeepBlue main menu, waiting for your input"
            switch ($selection)
            {
                'Security' {
                    $global:LogTarget = "Security"
                    $global:LogType = $LogPathSecurity
                    $selection2 = Read-Host $AppCMenuSub "$global:LogTarget sub menu, waiting for your input"
                    switch ($selection2)
                    {
                        'List' {
                            $global:LogFormat = $PipeList
                            RunDeepBlue
                            } 
                        'table' {
                            $global:LogFormat = $PipeTable
                            RunDeepBlue
                            }
                        'Grid' {
                            $global:LogFormat = $PipeGrid
                            RunDeepBlue
                            } 
                        'Html' {
                            $global:LogFormat = $PipeHtml
                            RunDeepBlue
                            } 
                        'Json' {
                            $global:LogFormat = $PipeJson
                            RunDeepBlue
                            } 
                        'Xml' {
                            $global:LogFormat = $PipeXml
                            RunDeepBlue
                            }
                        'Export' {
                            Write-Host $StatusCLoading
                            ExportLog("Security")
                            }
                        'Help' {
                            Clear-Host
                            Write-Host $BannerC
                            Write-Host $DBCLIHelp      
                            }
                        'Exit' {
                            ExitHard     
                            }                
                        'Back' {
                            AppCMenuMain
                            } 
                    }
                    pause
                } 
                'System' {
                    $global:LogTarget = "System"
                    $global:LogType = $LogPathSystem
                    $selection2 = Read-Host $AppCMenuSub "$global:LogTarget Menu, waiting for your input"
                    switch ($selection2)
                    {
                        'List' {
                            $global:LogFormat = $PipeList
                            RunDeepBlue
                            } 
                        'table' {
                            $global:LogFormat = $PipeTable
                            RunDeepBlue
                            }
                        'Grid' {
                            $global:LogFormat = $PipeGrid
                            RunDeepBlue
                            } 
                        'Html' {
                            $global:LogFormat = $PipeHtml
                            RunDeepBlue
                            } 
                        'Json' {
                            $global:LogFormat = $PipeJson
                            RunDeepBlue
                            } 
                        'Xml' {
                            $global:LogFormat = $PipeXml
                            RunDeepBlue
                            }
                        'Export' {
                            Write-Host $StatusCLoading
                            ExportLog("System")
                            }
                        'Help' {
                            Clear-Host
                            Write-Host $BannerC
                            Write-Host $DBCLIHelp      
                            }
                        'Exit' {
                            ExitHard
                            }              
                        'Back' {
                            AppCMenuMain
                            } 
                    }
                    pause
                } 
                'Application' {
                    $global:LogTarget = "Application"
                    $global:LogType = $LogPathApplication
                    $selection2 = Read-Host $AppCMenuSub "$global:LogTarget Menu, waiting for your input"
                    switch ($selection2)
                    {
                        'List' {
                            $global:LogFormat = $PipeList
                            RunDeepBlue
                            } 
                        'table' {
                            $global:LogFormat = $PipeTable
                            RunDeepBlue
                            }
                        'Grid' {
                            $global:LogFormat = $PipeGrid
                            RunDeepBlue
                            } 
                        'Html' {
                            $global:LogFormat = $PipeHtml
                            RunDeepBlue
                            } 
                        'Json' {
                            $global:LogFormat = $PipeJson
                            RunDeepBlue
                            } 
                        'Xml' {
                            $global:LogFormat = $PipeXml
                            RunDeepBlue
                            }
                        'Export' {
                            Write-Host $StatusCLoading
                            ExportLog("Application")
                            }
                        'Help' {
                            Clear-Host
                            Write-Host $BannerC
                            Write-Host $DBCLIHelp      
                            }
                        'Exit' {
                            ExitHard  
                            }              
                        'Back' {
                            AppCMenuMain
                            } 
                    }
                    pause
                } 
                'AppLocker' {
                    $global:LogTarget = "AppLocker"
                    $global:LogType = $LogPathAppLocker
                    $selection2 = Read-Host $AppCMenuSub "$global:LogTarget Menu, waiting for your input"
                    switch ($selection2)
                    {
                        'List' {
                            $global:LogFormat = $PipeList
                            RunDeepBlue
                            } 
                        'table' {
                            $global:LogFormat = $PipeTable
                            RunDeepBlue
                            }
                        'Grid' {
                            $global:LogFormat = $PipeGrid
                            RunDeepBlue
                            } 
                        'Html' {
                            $global:LogFormat = $PipeHtml
                            RunDeepBlue
                            } 
                        'Json' {
                            $global:LogFormat = $PipeJson
                            RunDeepBlue
                            } 
                        'Xml' {
                            $global:LogFormat = $PipeXml
                            RunDeepBlue
                            }
                        'Export' {
                            Write-Host $StatusCLoading
                            ExportLog("AppLocker")
                            }
                        'Help' {
                            Clear-Host
                            Write-Host $BannerC
                            Write-Host $DBCLIHelp      
                            }
                        'Exit' {
                            ExitHard  
                            }          
                        'Back' {
                            AppCMenuMain
                            } 
                    }
                    pause
                } 
                'PowerShell' {
                    $global:LogTarget = "PowerShell"
                    $global:LogType = $LogPathPowerShell
                    $selection2 = Read-Host $AppCMenuSub "$global:LogTarget Menu, waiting for your input"
                    switch ($selection2)
                    {
                        'List' {
                            $global:LogFormat = $PipeList
                            RunDeepBlue
                            } 
                        'table' {
                            $global:LogFormat = $PipeTable
                            RunDeepBlue
                            }
                        'Grid' {
                            $global:LogFormat = $PipeGrid
                            RunDeepBlue
                            } 
                        'Html' {
                            $global:LogFormat = $PipeHtml
                            RunDeepBlue
                            } 
                        'Json' {
                            $global:LogFormat = $PipeJson
                            RunDeepBlue
                            } 
                        'Xml' {
                            $global:LogFormat = $PipeXml
                            RunDeepBlue
                            }
                        'Export' {
                            Write-Host $StatusCLoading
                            ExportLog("PowerShell")
                            }
                        'Help' {
                            Clear-Host
                            Write-Host $BannerC
                            Write-Host $DBCLIHelp      
                            }
                        'Exit' {
                            ExitHard   
                            }           
                        'Back' {
                            DBCLIMenuMain
                            } 
                    }
                    pause
                } 
                'Sysmon' {
                    $global:LogTarget = "Sysmon"
                    $global:LogType = $LogPathSysmon
                    $selection2 = Read-Host $AppCMenuSub "$global:LogTarget Menu, waiting for your input"
                    switch ($selection2)
                    {
                        'List' {
                            $global:LogFormat = $PipeList
                            RunDeepBlue
                            } 
                        'table' {
                            $global:LogFormat = $PipeTable
                            RunDeepBlue
                            }
                        'Grid' {
                            $global:LogFormat = $PipeGrid
                            RunDeepBlue
                            } 
                        'Html' {
                            $global:LogFormat = $PipeHtml
                            RunDeepBlue
                            } 
                        'Json' {
                            $global:LogFormat = $PipeJson
                            RunDeepBlue
                            } 
                        'Xml' {
                            $global:LogFormat = $PipeXml
                            RunDeepBlue
                            }
                        'Export' {
                            Write-Host $StatusCLoading
                            ExportLog("Sysmon")
                            }
                        'Help' {
                            Clear-Host
                            Write-Host $BannerC
                            Write-Host $DBCLIHelp      
                            }
                        'Exit' {
                            ExitHard   
                            }           
                        'Back' {
                            AppCMenuMain
                            } 
                    }
                    pause
                } 
                'WMI' {
                    $global:LogTarget = "WMI"
                    $global:LogType = $LogPathWMI
                    $selection2 = Read-Host $AppCMenuSub "$global:LogTarget Menu, waiting for your input"
                    switch ($selection2)
                    {
                        'List' {
                            $global:LogFormat = $PipeList
                            RunDeepBlue
                            } 
                        'table' {
                            $global:LogFormat = $PipeTable
                            RunDeepBlue
                            }
                        'Grid' {
                            $global:LogFormat = $PipeGrid
                            RunDeepBlue
                            } 
                        'Html' {
                            $global:LogFormat = $PipeHtml
                            RunDeepBlue
                            } 
                        'Json' {
                            $global:LogFormat = $PipeJson
                            RunDeepBlue
                            } 
                        'Xml' {
                            $global:LogFormat = $PipeXml
                            RunDeepBlue
                            }
                        'Export' {
                            Write-Host $StatusCLoading
                            ExportLog("WMI")
                            }
                        'Help' {
                            Clear-Host
                            Write-Host $BannerC
                            Write-Host $DBCLIHelp      
                            }
                        'Exit' {
                            ExitHard  
                            }           
                        'Back' {
                            AppCMenuMain
                            } 
                    }
                    pause
                } 
                'Export' {
                Write-Host $StatusCLoading
                ExportLog("Security","System","Application","AppLocker","PowerShell","Sysmon","WMI")                 
                }
                'Import' {
                    Write-Host $StatusCLoading
                    RunImport
                } 
                'help' {
                Clear-Host
                Write-Host $BannerC
                Write-Host $DBCLIHelp                    
                }
                'Wipe' {
                AppCWipe
                }
                'Exit' {
                ExitHard
                }
                'Back' {
                Show-Menu
                }
                '' {
                clear
                DBCLIMenuMain
                }
            }
            pause
        }
        until ($selection -eq 'Back' -or $selection -eq '')
    }
    else
    {
        Write-Host "Intialization process has failed..."
    }
}

function StartDBCLI($Source) {   
    #Clear
    clear

    # Make space for download status bar
    Write-Host $StatusLoadingLineBreak

    # Notify DBCLI Source URL and hash based on request
    if ($Source -eq "MAIN SOURCE"){
        Write-Host "[MAIN SOURCE]: " -ForegroundColor Green -NoNewline; Write-Host $AppCURLMain -ForegroundColor Yellow
        Write-Host "    [SHA-256]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppCHashMain}" -ForegroundColor Yellow `n 
    }
    if ($Source -eq "MIRROR SOURCE"){
        Write-Host "[MIRROR SOURCE]: " -ForegroundColor Green -NoNewline; Write-Host $AppCURLMirror -ForegroundColor Yellow
        Write-Host "      [SHA-256]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppCHashMirror}" -ForegroundColor Yellow `n
    }

    # Create the ParentAppCFolder in ParentFolder (Also hiding the Powershell Output)
    $null = new-item -path "$UserDesktopPath" -name $ParentFolder -itemtype directory -Force
    Write-Host $StatusCCreatedAppCFolder -ForegroundColor Green

    # Change the directory to ParentAppCFolder
    set-location "$UserDesktopPath\$ParentFolder"
    Write-Host $StatusCChangedDirToAppCFolder -ForegroundColor Green

    # Check existing DeepBlue folder, if exist, we delete to get a new untampered copy.
    if (Test-Path .\$AppCName) {
        Remove-Item .\$AppCName -Recurse
    }
    Write-Host $StatusCCheckAndRemoveExisting -ForegroundColor Green

    # Check for Download request
    if ($Source -eq "MAIN SOURCE"){
        $global:AppCURLUsed = $AppCURLMain
        $AppCHashUsed = $AppCHashMain
    }
    if ($Source -eq "MIRROR SOURCE"){
        $global:AppCURLUsed = $AppCURLMirror
        $AppCHashUsed = $AppCHashMirror
    }

    # Download zip file from Repo
    Write-Host $StatusCDownloadApp -ForegroundColor Green
    Clear-Variable -Name "Source" -Scope Global
    Invoke-WebRequest -Uri $AppCURLUsed -OutFile .\$AppCName.zip

    # Download DBCLI
    Write-Host $StatusCHashCheck -ForegroundColor Green
    $HashDownload = Get-FileHash .\$AppCName.zip | Select-Object -ExpandProperty Hash
 

        # Hash Diff Allow/Deny Progression    
        if ($AppCHashUsed -eq $HashDownload){
            $AppCHashValid = "True"
            Write-Host "  [EXPECTED]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppCHashUsed}" -ForegroundColor Green
            Write-Host "[DOWNLOADED]: " -ForegroundColor Green -NoNewline; Write-Host "{$HashDownload}" -ForegroundColor Green
            Write-Host "              |------------------------ [ HASH VALID ] ------------------------|`n" -ForegroundColor Yellow
            
        }
        else {
            $AppCHashValid = "False"
            Write-Host "  [EXPECTED]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppCHashUsed}" -ForegroundColor Green
            Write-Host "[DOWNLOADED]: " -ForegroundColor Green -NoNewline; Write-Host "{$HashDownload}" -ForegroundColor Red
            Write-Host "              |----------------------- [ HASH INVALID ] -----------------------|`n" -ForegroundColor Red
            Write-Host "Hash INVALID, URL possibly hijacked or updated. Removed $AppCName.zip, Use MIRROR SOURCE for saftey." -ForegroundColor Red
            set-location "$UserDesktopPath\$ParentFolder"
            Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppCName.zip"
            Read-Host "Press any key to return to the main menu"
        }

        if ($AppCHashValid -eq "True"){
        # Extract, rename, delete downloaded zip file
        Write-Host $StatusCExtractedApp -ForegroundColor Green
        Expand-Archive .\$AppCName.zip .\ -Force
        Rename-Item .\$AppCName-master .\$AppCName
        Remove-Item .\$AppCName.zip
        Write-Host $StatusCRemoveDownload -ForegroundColor Green

        if ($AppCHashValid -eq "False"){
        Show-Menu
        }
    
    # Change the directory to AppCName
    set-location "$UserDesktopPath\$ParentFolder\$AppCFolder"
    Write-Host $StatusCChangedDirToAppFolder -ForegroundColor Green

    # Check if staging and initialization is complete
    $HealthCheck = "True"
    
    # Call DBCLIMenu
    DBCLIMenuMain
    }
}

function AppCWipe {
    do {
     # Confirm from user first, then check for DeepBlue folder, if exists, delete it.
    $selectionAppCWipe = Read-Host "Are you sure you want wipe $AppCFolder? (Y/N)"
    switch ($selectionAppCWipe)
    {
        'Y' {
            if (Test-Path "$UserDesktopPath\$ParentFolder\$AppCFolder") {
                set-location "$UserDesktopPath\$ParentFolder"
                Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppCFolder"
                Show-Menu
                return
                }
        } 
        'N' {
            return
            DBCLIMenuMain
        }
        '' {
            AppCWipe
        }
    }
 }
 until ($selection -eq 'Y' -or $selection -eq 'N' -or $selection -eq '')
}

# VARIABLES - AppD (RemoteAccess) ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# VARIABLES - AppD (EDR)
$BannerD = @"
_________________________________________________________________________________

    ____  ________  _______  ____________   ___   ____________________________
   / __ \/ ____/  |/  / __ \/_  __/ ____/  /   | / ____/ ____/ ____/ ___/ ___/
  / /_/ / __/ / /|_/ / / / / / / / __/    / /| |/ /   / /   / __/  \__ \\__ \ 
 / _, _/ /___/ /  / / /_/ / / / / /___   / ___ / /___/ /___/ /___ ___/ /__/ / 
/_/ |_/_____/_/  /_/\____/ /_/ /_____/  /_/  |_\____/\____/_____//____/____/
                      Monitored by CyberSeidon
_________________________________________________________________________________`n
"@

# VARIABLES D
$AppDName = "Remote Access"
$AppDDescription = "Deploy Remote Access"
    $AppDFolder = "RemoteAccess"
    # URLs (URLS are found in Source check)

$AppDOrgKey = ""
$AppDAgentFileName = ""
# Install command moved inside of the AppDRemoteAccessInstall function
# $AppDInstallCommand = “msiexec /i “action1_agent($AppDOrgKey).msi” /quiet”
$AppDUninstallCommand = 'msiexec /uninstall "C:\Windows\Action1\action1_agent.msi" /quiet'
$AppDRemoteAccessExists = "False"


# VARIABLES D - Status notifications
    $StatusDDetectedExisting = ">>> [ Detected existing $AppDName files in $UserDesktopPath\$ParentFolder\$AppDFolder ]`n"
    $StatusDRemoveExisting = ">>> [ Removed existing $AppDName files in $UserDesktopPath\$ParentFolder\$AppDFolder ]`n"
    $StatusDCreatedAppDFolder = ">>>> [ Adding new directory $UserDesktopPath\$ParentFolder\$AppDFolder ]`n"
    $StatusDChangedDirToAppDFolder = ">>>>> [ Changed working directory to $UserDesktopPath\$ParentFolder\$AppDFolder ]`n"
    $StatusDDownloadApp = ">>>>>> [ Downloading agent"
    $StatusDHashCheck = ">>>>>>> [ Checking hash ]`n"
    $StatusDBootUp = ">>>>>>>> [ Booting up `"$AppDName`" ]`n"
    $StatusDReady = ">>>>>>>>> [ $AppDName is Ready for Hunting... ]`n"
    $StatusDWipe = ">>>>>>>>>> [ Wiping $AppDName ]"


$AppDMenuMain = @"

                            $Source
                 __[ REMOTE ACCESS MAIN MENU ]__
                |                               |
                |   [AK] | AK                   |
                |   [EW] | EDMOND WONG          |                
                |   [GP] | GRACE PARK           |
                |   [IC] | INDIVIDUAL CLIENTS   |
                |   [JG] | JASON GREENBERG      |     	
                |   [JM] | JUDY MOCK            |
                |  [KNA] | KIM & ASSOCIATES     |
                |  [PMC] | PALISIDES MEDICAL    |
                |   [RR] | RAPID RESPONSE       |
                |   [SB] | SANDBOX              |
                |   [SY] | SUYON YI             |
                |  [REM] | Remove EDR           |
                | [Exit] | Hard Exit            |
                | [Back] | Back to Main Menu    |
                |_______________________________|`n `n
"@    


function AppDRemoteAccessInstall($AppDOrgKey, $Source){
  # Check if Remote Access is already installed and files are detected, we throw exception and go to AppDMenu for potential uninstall option
        if (Test-Path "C:\Windows\Action1\action1_agent.exe") {
            Write-Host `n"$StatusBlankSpace [ Remote Access ALREADY EXISTS! ]" -ForegroundColor White -Background DarkRed
            Write-Host "$StatusBlankSpace [ HOSTNAME: $HostName ]"`n -ForegroundColor White
            $AppDRemoteAccessExists = "True"
            pause
            # Exit back to AppDMenu
            #AppDMenuMain
        }
        else {

  # Source check
        # Main Source will follow this flow
        if ($Source -eq "MAIN SOURCE"){
            if ($AppDOrgKey -eq "AK"){
                $AppDURLMain = "https://app.action1.com/agent/bd9e9504-b40b-11ed-9c60-5b71e351ba63/Windows/agent(AK_-_ADAM_KIM).msi"
                $AppDHashMain = "064768699B50DF63FC34D176B6062FF23D58074639CC4E2550B08B5C33C67AFB"
                $AppDAgentFileName = "action1_agent(AK_-_ADAM_KIM)"
            }
            if ($AppDOrgKey -eq "EW"){
                $AppDURLMain = "https://app.action1.com/agent/ca8e96b4-32f6-11ee-9ea7-83eb080d2617/Windows/agent(EW_-_EDMOND_WONG).msi"
                $AppDHashMain = "75587616020A06E3F08F9D93F537828DEE5626C93A24B5312274EC239957CEE8"
                $AppDAgentFileName = "action1_agent(EW_-_EDMOND_WONG)"
            }
            if ($AppDOrgKey -eq "GP"){
                $AppDURLMain = "https://app.action1.com/agent/f82c7ce4-9c3c-11ee-92f1-3b9755e10bac/Windows/agent(GP_-_GRACE_PARK).msi"
                $AppDHashMain = "13AD3A6AFCDCF2A17C2BE2CD1747FC1B2E9402F02877E6FA7069DEF394DC95DE"
                $AppDAgentFileName = "action1_agent(GP_-_GRACE_PARK)"
            }
            if ($AppDOrgKey -eq "IC"){
                $AppDURLMain = "https://app.action1.com/agent/f19e6144-afc9-11ee-b2a5-1deb4e8ddb33/Windows/agent(IC-_INDIVIDUAL_CLIENTS).msi"
                $AppDHashMain = "94222009F399CB90F9221484A0A65CAF3DF6C13F83346CDC6E1AF279E3C63E8E"
                $AppDAgentFileName = "action1_agent(IC-_INDIVIDUAL_CLIENTS)"
            }
            if ($AppDOrgKey -eq "JG"){
                $AppDURLMain = "https://app.action1.com/agent/a299a104-ec41-11ed-adbb-23da6e95e2ea/Windows/agent(JG_-_JASON_GREENBERG).msi"
                $AppDHashMain = "8144E2C65A4DDA569FF76B6462672A465FD4FC060997FB41F0366DB106688510"
                $AppDAgentFileName = "action1_agent(JG_-_JASON_GREENBERG)"
            }
            if ($AppDOrgKey -eq "JM"){
                $AppDURLMain = "https://app.action1.com/agent/cc7510a4-feaf-11ee-ad29-119b83a5aae4/Windows/agent(JM_-_JUDY_MOCK).msi"
                $AppDHashMain = "FFC57D3CAAAEEF866B4482C8E1497CEA1D53E749A88F03A2A901797A3330B76D"
                $AppDAgentFileName = "action1_agent(JM_-_JUDY_MOCK)"
            }
            if ($AppDOrgKey -eq "KnA"){
                $AppDURLMain = "https://app.action1.com/agent/69a4c614-c336-11ed-9871-35b181befa3f/Windows/agent(KnA_-_KIM_ASSOCIATES).msi"
                $AppDHashMain = "1E8A7050FB782EC3F8AF859813529E0BB74F9AA2A60F96E5CE7A80E50470ED6E"
                $AppDAgentFileName = "action1_agent(KnA_-_KIM_ASSOCIATES)"
            }
            if ($AppDOrgKey -eq "PMC"){
                $AppDURLMain = "https://app.action1.com/agent/7c20e9a4-b4b7-11ed-a067-bd7ac9f64a19/Windows/agent(PMC_-_PALISADES_MEDICAL_CENTER).msi"
                $AppDHashMain = "19EB342EE269D211906E3D926045964EBE3CCD52D89F17FA733D8D24A082637A"
                $AppDAgentFileName = "action1_agent(PMC_-_PALISADES_MEDICAL_CENTER)"
            }
            if ($AppDOrgKey -eq "RR"){
                $AppDURLMain = "https://app.action1.com/agent/e2222381-865e-11ee-9dcf-67aae8813155/Windows/agent(RR_-_RAPID_RESPONSE).msi"
                $AppDHashMain = "49D3C700AF0601BA5A3311A877DA13CE67785BD67E11B386FA090A785A788672"
                $AppDAgentFileName = "action1_agent(RR_-_RAPID_RESPONSE)"
            }
            if ($AppDOrgKey -eq "SB"){
                $AppDURLMain = "https://app.action1.com/agent/580d1074-33f5-11ef-95f6-abb932ce4201/Windows/agent(SB_-_SANDBOX).msi"
                $AppDHashMain = "388217B0619AC7B4599FF7A30ED0A4D3928DA0A60EDD90A549519E91C18DDE52"
                $AppDAgentFileName = "action1_agent(SB_-_SANDBOX)"
            }
            if ($AppDOrgKey -eq "SY"){
                $AppDURLMain = "https://app.action1.com/agent/cd55fad3-5a58-11ee-a0f9-916686d13b73/Windows/agent(SY_-_SUYON_YI).msi"
                $AppDHashMain = "06D92FFC185F9E7768F831845428B0E5E6D9C3D58910A2AAF31AD252A132116D"
                $AppDAgentFileName = "action1_agent(SY_-_SUYON_YI)"
            }
        }
        # Mirror Source will follow this flow
         if ($Source -eq "MIRROR SOURCE"){
            if ($AppDOrgKey -eq "AK"){
                $AppDURLMirror = "https://github.com/resv/THC-PRO/raw/main/THC-PRO-Mirror-Apps/RemoteAccess/action1_agent(AK_-_ADAM_KIM).msi"
                $AppDHashMirror = "064768699B50DF63FC34D176B6062FF23D58074639CC4E2550B08B5C33C67AFB"
                $AppDAgentFileName = "action1_agent(AK_-_ADAM_KIM)"
            }
            if ($AppDOrgKey -eq "EW"){
                $AppDURLMirror = "https://github.com/resv/THC-PRO/raw/main/THC-PRO-Mirror-Apps/RemoteAccess/action1_agent(EW_-_EDMOND_WONG).msi"
                $AppDHashMirror = "75587616020A06E3F08F9D93F537828DEE5626C93A24B5312274EC239957CEE8"
                $AppDAgentFileName = "action1_agent(EW_-_EDMOND_WONG)"
            }
            if ($AppDOrgKey -eq "GP"){
                $AppDURLMirror = "https://github.com/resv/THC-PRO/raw/main/THC-PRO-Mirror-Apps/RemoteAccess/action1_agent(GP_-_GRACE_PARK).msi"
                $AppDHashMirror = "13AD3A6AFCDCF2A17C2BE2CD1747FC1B2E9402F02877E6FA7069DEF394DC95DE"
                $AppDAgentFileName = "action1_agent(GP_-_GRACE_PARK)"
            }
            if ($AppDOrgKey -eq "IC"){
                $AppDURLMirror = "https://github.com/resv/THC-PRO/raw/main/THC-PRO-Mirror-Apps/RemoteAccess/action1_agent(IC-_INDIVIDUAL_CLIENTS).msi"
                $AppDHashMirror = "94222009F399CB90F9221484A0A65CAF3DF6C13F83346CDC6E1AF279E3C63E8E"
                $AppDAgentFileName = "action1_agent(IC-_INDIVIDUAL_CLIENTS)"
            }
            if ($AppDOrgKey -eq "JG"){
                $AppDURLMirror = "https://github.com/resv/THC-PRO/raw/main/THC-PRO-Mirror-Apps/RemoteAccess/action1_agent(JG_-_JASON_GREENBERG).msi"
                $AppDHashMirror = "8144E2C65A4DDA569FF76B6462672A465FD4FC060997FB41F0366DB106688510"
                $AppDAgentFileName = "action1_agent(JG_-_JASON_GREENBERG)"
            }
            if ($AppDOrgKey -eq "JM"){
                $AppDURLMirror = "https://github.com/resv/THC-PRO/raw/main/THC-PRO-Mirror-Apps/RemoteAccess/action1_agent(JM_-_JUDY_MOCK).msi"
                $AppDHashMirror = "FFC57D3CAAAEEF866B4482C8E1497CEA1D53E749A88F03A2A901797A3330B76D"
                $AppDAgentFileName = "action1_agent(JM_-_JUDY_MOCK)"
            }
            if ($AppDOrgKey -eq "KnA"){
                $AppDURLMirror = "https://github.com/resv/THC-PRO/raw/main/THC-PRO-Mirror-Apps/RemoteAccess/action1_agent(KnA_-_KIM_ASSOCIATES).msi"
                $AppDHashMirror = "1E8A7050FB782EC3F8AF859813529E0BB74F9AA2A60F96E5CE7A80E50470ED6E"
                $AppDAgentFileName = "action1_agent(KnA_-_KIM_ASSOCIATES)"
            }
            if ($AppDOrgKey -eq "PMC"){
                $AppDURLMirror = "https://github.com/resv/THC-PRO/raw/main/THC-PRO-Mirror-Apps/RemoteAccess/action1_agent(PMC_-_PALISADES_MEDICAL_CENTER).msi"
                $AppDHashMirror = "19EB342EE269D211906E3D926045964EBE3CCD52D89F17FA733D8D24A082637A"
                $AppDAgentFileName = "action1_agent(PMC_-_PALISADES_MEDICAL_CENTER)"
            }
            if ($AppDOrgKey -eq "RR"){
                $AppDURLMirror = "https://github.com/resv/THC-PRO/raw/main/THC-PRO-Mirror-Apps/RemoteAccess/action1_agent(RR_-_RAPID_RESPONSE).msi"
                $AppDHashMirror = "49D3C700AF0601BA5A3311A877DA13CE67785BD67E11B386FA090A785A788672"
                $AppDAgentFileName = "action1_agent(RR_-_RAPID_RESPONSE)"
            }
            if ($AppDOrgKey -eq "SB"){
                $AppDURLMirror = "https://github.com/resv/THC-PRO/raw/main/THC-PRO-Mirror-Apps/RemoteAccess/action1_agent(SB_-_SANDBOX).msi"
                $AppDHashMirror = "388217B0619AC7B4599FF7A30ED0A4D3928DA0A60EDD90A549519E91C18DDE52"
                $AppDAgentFileName = "action1_agent(SB_-_SANDBOX)"
            }
            if ($AppDOrgKey -eq "SY"){
                $AppDURLMirror = "https://github.com/resv/THC-PRO/raw/main/THC-PRO-Mirror-Apps/RemoteAccess/action1_agent(SY_-_SUYON_YI).msi"
                $AppDHashMirror = "06D92FFC185F9E7768F831845428B0E5E6D9C3D58910A2AAF31AD252A132116D"
                $AppDAgentFileName = "action1_agent(SY_-_SUYON_YI)"
            }
        }

        # Announce source and hash, assign value to variables
        if ($Source -eq "MAIN SOURCE"){
            $global:AppDURLUsed = $AppDURLMain
            $AppDHashUsed = $AppDHashMain
            Write-Host "[MAIN SOURCE]: " -ForegroundColor Green -NoNewline; Write-Host $AppDURLMain -ForegroundColor Yellow
            Write-Host "    [SHA-256]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppDHashMain}" -ForegroundColor Yellow `n 
        }
        
        if ($Source -eq "MIRROR SOURCE"){
            $global:AppDURLUsed = $AppDURLMirror
            $AppDHashUsed = $AppDHashMirror
            Write-Host "[MIRROR SOURCE]: " -ForegroundColor Green -NoNewline; Write-Host $AppDURLMirror -ForegroundColor Yellow
            Write-Host "      [SHA-256]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppDHashMirror}" -ForegroundColor Yellow `n
        }       

        # Download zip file from Repo
        Write-Host "$StatusDDownloadApp from $Source ]"`n -ForegroundColor Green
        Invoke-WebRequest -Uri $AppDURLUsed -OutFile .\$AppDAgentFileName

        # Grab and check hash
        Write-Host $StatusDHashCheck -ForegroundColor Green
        $HashDownload = Get-FileHash .\$AppDAgentFileName | Select-Object -ExpandProperty Hash
    

            # Hash Diff Allow/Deny Progression    
            if ($AppDHashUsed -eq $HashDownload){
                $AppDHashValid = "True"
                Write-Host "  [EXPECTED]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppDHashUsed}" -ForegroundColor Green
                Write-Host "[DOWNLOADED]: " -ForegroundColor Green -NoNewline; Write-Host "{$HashDownload}" -ForegroundColor Green
                Write-Host "              |------------------------ [ HASH VALID ] ------------------------|`n" -ForegroundColor Yellow
                # Change the directory to AppDName
                set-location "$UserDesktopPath\$ParentFolder\$AppDFolder"
                Write-Host $StatusDBootUp -ForegroundColor Green
                # Install starts here
                Write-Host `n"$StatusBlankSpace[ Deploying Remote Access... ]" -ForegroundColor White -Background DarkRed
                Write-Host `n""
                Invoke-Expression "msiexec /i `"$UserDesktopPath\$ParentFolder\$AppDFolder\$AppDAgentFileName`" /quiet"
                Write-Host "$StatusBlankSpace[ DEPLOYMENT SUCCESS | HOSTNAME: $HostName | ORGAINIZATION: $AppDOrgName ]" -ForegroundColor White -Background DarkRed
                Write-Host `n""
                Read-host "Press any key to return to the $AppDName menu"
                AppDMenuMain
            }
            else {
                $AppDHashValid = "False"
                Write-Host "  [EXPECTED]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppDHashUsed}" -ForegroundColor Green
                Write-Host "[DOWNLOADED]: " -ForegroundColor Green -NoNewline; Write-Host "{$HashDownload}" -ForegroundColor Red
                Write-Host "              |---------------------- [ HASH INVALID ] ----------------------|`n" -ForegroundColor Red
                Write-Host "Hash INVALID, URL possibly hijacked or updated. Removed $AppDAgentFileName, use MIRROR SOURCE for saftey." -ForegroundColor Red
                set-location "$UserDesktopPath\$ParentFolder"
                Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppDFolder"
                Read-Host "Press any key to return to the main menu"
                Show-Menu
            }
        }
}

function StartRemoteAccess($Source){   
    #Clear
    clear

        # Make space for download status bar
        Write-Host $StatusLoadingLineBreak

        # Create the in ParentFolder (Also hiding the Powershell Output)
        $null = new-item -path "$UserDesktopPath" -name $ParentFolder -itemtype directory -Force
        Write-Host $StatusCreatedParentFolder -ForegroundColor Green

        # Change the directory to ParentFolder
        set-location "$UserDesktopPath\$ParentFolder"
        Write-Host $StatusChangedDirToParentFolder -ForegroundColor Green

        # Check existing Remote Access folder, if exist, we delete for a fresh start.
        if (Test-Path .\$AppDFolder) {
            Write-Host $StatusDDetectedExisting -ForegroundColor Green
            Remove-Item .\$AppDFolder -Recurse
            Write-Host $StatusDRemoveExisting -ForegroundColor Green
        }

        # Create new Remote Access Folder, change dir to Remote Access folder
        $null = New-Item -Path .\ -Name "$AppDFolder" -ItemType "directory" -Force
        Write-Host $StatusDCreatedAppDFolder -ForegroundColor Green
        set-location "$UserDesktopPath\$ParentFolder\$AppDFolder"
        Write-Host $StatusDChangedDirToAppDFolder -ForegroundColor Green      

        AppDMenuMain($Source)
}




function AppDRemoteAccessRemove {

    if (Test-Path "C:\Windows\Action1\action1_agent.exe") {
        $AppDRemoteAccessExists = "True"
        Write-Host `n""
        Write-Host "[ Remote Access Agent detected, removing.. ]" -ForegroundColor White -Background DarkRed
    }
    else {
        Write-Host "" -ForegroundColor White -Background DarkRed
        Write-Host "[ No Remote Access agent detected, possibly already uninstalled, check logs @ "C:\Windows\Action1\logs" ]" -ForegroundColor White -Background DarkRed
        Write-Host "" -ForegroundColor White -Background DarkRed
        $AppDRemoteAccessExists = "False"
        pause
    }

    if ($AppDRemoteAccessExists -eq "True") {
    Invoke-Expression $AppDUninstallCommand
    $AppDRemoteAccessRemoveSuccessful = "True"
    }

    If ($AppDRemoteAccessRemoveSuccessful -eq "True"){
    Write-Host `n""
    Write-Host "Remote Access Removal $HostName Successful" -ForegroundColor White -Background DarkRed
    Write-Host `n""
    Write-Host "Log files remain at "C:\Windows\Action1\logs"" -ForegroundColor White -Background DarkRed
    Write-Host `n""
    pause
    }
}


function AppDMenuMain($Source){      
    
    do
    {  
        $selectionAppD = Read-Host $BannerD $AppDMenuMain "$AppDName $Source main menu, select org, waiting for your input"
        switch ($selectionAppD)
        {
            
            'AK' {
                $AppDOrgKey = "AK"
                $AppDOrgName = "ADAM KIM"
                AppDRemoteAccessInstall $AppDOrgKey $Source
            }
            'EW' {
                $AppDOrgKey = "EW"
                $AppDOrgName = "EDMOND WONG"
                AppDRemoteAccessInstall $AppDOrgKey $Source
            }
            'GP' {
                $AppDOrgKey = "GP"
                $AppDOrgName = "GRACE PARK"
                AppDRemoteAccessInstall $AppDOrgKey $Source
            }
            'IC' {
                $AppDOrgKey = "IC"
                $AppDOrgName = "INDIVIDUAL CLIENTS"
                AppDRemoteAccessInstall $AppDOrgKey $Source
            }
            'JG' {
                $AppEOrgKey = "JG"
                $AppDOrgName = "JASON GREENBERG"
                AppDRemoteAccessInstall $AppDOrgKey $Source
            }
            'JM' {
                $AppDOrgKey = "JM"
                $AppDOrgName = "JUDY MOCK"
                AppDRemoteAccessInstall $AppDOrgKey $Source
            }
            'KnA' {
                $AppDOrgKey = "KnA"
                $AppDOrgName = "KIM & ASSOCIATES"
                AppDRemoteAccessInstall $AppDOrgKey $Source
            }
            'PMC' {
                $AppDOrgKey = "PMC"
                $AppDOrgName = "PALISIDES MEDICAL CENTER"
                AppDRemoteAccessInstall $AppDOrgKey $Source
            }
            'RR' {
                $AppDOrgKey = "RR"
                $AppDOrgName = "RAPID RESPONSE"
                AppDRemoteAccessInstall $AppDOrgKey $Source
            }
            'SB' {
                $AppDOrgKey = "SB"
                $AppDOrgName = "SANDBOX"
                AppDRemoteAccessInstall $AppDOrgKey $Source
            }
            'SY' {
                $AppDOrgKey = "SY"
                $AppDOrgName = "SUYON YI"
                AppDRemoteAccessInstall $AppDOrgKey $Source
            }
            'REM' {
                AppDRemoteAccessRemove
                Clear
                Show-Menu
            }
            'Exit' {
                ExitHard
            }
            'Back' {
                clear
                Show-Menu
            }
            '' {
            clear
            }
        }
    }
    until ($selectionAppD -eq 'IC' -or $selectionAppD -eq 'AK' -or $selectionAppD -eq 'SYY' -or $selectionAppD -eq 'JG' -or $selectionAppD -eq 'GP' -or $selectionAppD -eq 'EW' -or $selectionAppD -eq 'KNA' -or $selectionAppD -eq 'JM' -or $selectionAppD -eq 'SB' -or $selectionAppD -eq 'RR' -or $selectionAppD -eq 'REM' -or $selectionAppD -eq 'Back')
    }




# VARIABLES - AppE (EDR)
$BannerE = @"
_________________________________________________________________________________
                            __________  ____ 
                           / ____/ __ \/ __ \
                          / __/ / / / / /_/ /
                         / /___/ /_/ / _, _/ 
                        /_____/_____/_/ |_|  
                      Monitored by CyberSeidon
_________________________________________________________________________________`n
"@
$AppEName = "EDR"
$AppEDescription = "Endpoint Detection & Response"

$AppEMenuMain = @"

                 ________[ EDR Main Menu ]_______
                |                                |
                |   [IC]  | Individual Clients   |
                |   [AK]  | AK                   |
                |  [SYY]  | Suyon Yi             |
                |   [JG]  | Jason A. Greenberg   |
                |   [GP]  | Grace S. Park        |     	
                |   [EW]  | Edmond Wong          |
                |  [KNA]  | Kim & Associates     |
                |   [JM]  | Judy Mock            |
                |   [SB]  | Sand box             |    
                |   [RR]  | Rapid Response       |
                |  [REM]  | Remove EDR           |
                | [Exit]  | Hard Exit            |
                | [Back]  | Back to Main Menu    |
                |________________________________|`n `n
"@    

$AppEOrgKey = ""

$AppEK1 = "ce736ef4"
$AppEK2 = "c365dc7a"
$AppEK3 = "4166f296"
$AppEK4 = "acd52a65"
$AppEKALL = "$AppEK1$AppEK2$AppEK3$AppEK4"
$AppEURL = "https://huntress.io/download/$AppEKALL"
$AppEUninstallCommand = "& 'C:\Program Files\Huntress\Uninstall.exe' `/S"
$AppEEDRExists = "False"

function AppFEDRInstall($AppEOrgKey){
    # If EDR files are detected, we throw exception and leave
    if (Test-Path "C:\Program Files\Huntress\") {
        Write-Host `n"$StatusBlankSpace [ EDR ALREADY EXISTS! ]" -ForegroundColor White -Background DarkRed
        Write-Host "$StatusBlankSpace [ HOSTNAME: $HostName ]"`n -ForegroundColor White
        pause
    }
    # If EDR files are not detected, we deploy
    else {
        Write-Host `n"$StatusBlankSpace[ Deploying EDR... ]" -ForegroundColor White -Background DarkRed
        Write-Host `n""
        (New-Object Net.WebClient).DownloadFile($AppEURL,$env:temp+'/HuntressInstaller.exe');iex $env:temp'\HuntressInstaller.exe /S /ACCT_KEY=$AppEKALL /ORG_KEY=$AppEOrgKey'
        Write-Host "$StatusBlankSpace[ DEPLOYMENT SUCCESS | HOSTNAME: $HostName | ORGAINIZATION: $AppEOrgName ]" -ForegroundColor White -Background DarkRed
        Write-Host `n""
        pause 
    }
}

function AppFEDRRemove {
    #Set-Location "C:\Program Files\Huntress\"

    if (Test-Path "C:\Program Files\Huntress\") {
        $AppEEDRExists = "True"
        Write-Host `n""
        Write-Host "[ EDR files detected, removing.. ]" -ForegroundColor White -Background DarkRed
    }
    else {
        Write-Host "" -ForegroundColor White -Background DarkRed
        Write-Host "[ EDR files not found at $AppEUninstallCommand, possibly no EDR or location differs]" -ForegroundColor White -Background DarkRed
        Write-Host "" -ForegroundColor White -Background DarkRed
        $AppEEDRExists = "False"
        pause
    }

    if ($AppEEDRExists -eq "True") {
    Invoke-Expression $AppEUninstallCommand
    Write-Host `n""
    Write-Host "EDR Removal $HostName Successful" -ForegroundColor White -Background DarkRed
    Write-Host `n""
    pause
    }
}

function StartEDR{      
    clear
    do
    {  
        $selectionAppE = Read-Host $BannerE $AppEMenuMain "$AppEName main menu, select org ,waiting for your input"
        switch ($selectionAppE)
        {
            'IC' {
                $AppEOrgKey = "IC"
                $AppEOrgName = "Individual Clients"
                AppFEDRInstall($AppEOrgkey)
                Show-Menu
            }
            'AK' {
                $AppEOrgKey = "AK"
                $AppEOrgName = "Adam Kim"
                AppFEDRInstall($AppEOrgkey)
                
            }
            'SYY' {
                $AppEOrgKey = "SYY"
                $AppEOrgName = "Suyon Yi"
                AppFEDRInstall($AppEOrgkey)
                Show-Menu
            }
            'JG' {
                $AppEOrgKey = "JG"
                $AppEOrgName = "Law Office of Jason A. Greenberg"
                AppFEDRInstall($AppEOrgkey)
                Show-Menu
            }
            'GP' {
                $AppEOrgKey = "GP"
                $AppEOrgName = "Grace S. Park"
                AppFEDRInstall($AppEOrgkey)
                Show-Menu
            }
            'EW' {
                $AppEOrgKey = "EW"
                $AppEOrgName = "Edmond Wong"
                AppFEDRInstall($AppEOrgkey)
                Show-Menu
            }
            'KnA' {
                $AppEOrgKey = "KnA"
                $AppEOrgName = "Kim & Associates"
                AppFEDRInstall($AppEOrgkey)
                Show-Menu
            }
            'JM' {
                $AppEOrgKey = "JM"
                $AppEOrgName = "Judy Mock Law Office"
                AppFEDRInstall($AppEOrgkey)
                Show-Menu
            }
            'SB' {
                $AppEOrgKey = "SB"
                $AppEOrgName = "Sand Box By CyberSeidon"
                AppFEDRInstall($AppEOrgkey)
                Show-Menu
            }
            'RR' {
                $AppEOrgKey = "RR"
                $AppEOrgName = "Rapid Response"
                AppFEDRInstall($AppEOrgkey)
                Show-Menu
            }
            'REM' {
                $AppEOrgKey = "REM"
                $AppEOrgName = "Remove EDR"
                AppFEDRRemove
                Clear
                Show-Menu
            }
            'Exit' {
                ExitHard
            }
            'Back' {
                clear
                Show-Menu
            }
            '' {
            clear
            }
        }
    }
    until ($selectionAppE -eq 'IC' -or $selectionAppE -eq 'AK' -or $selectionAppE -eq 'SYY' -or $selectionAppE -eq 'JG' -or $selectionAppE -eq 'GP' -or $selectionAppE -eq 'EW' -or $selectionAppE -eq 'KNA' -or $selectionAppE -eq 'JM' -or $selectionAppE -eq 'SB' -or $selectionAppE -eq 'RR' -or $selectionAppE -eq 'REM' -or $selectionAppE -eq 'Back')
    }


# VARIABLES - AppF (Autoruns)
$BannerF = @"
_________________________________________________________________________________
                    ___   __  ____________  ____  __  ___   _______
                   /   | / / / /_  __/ __ \/ __ \/ / / / | / / ___/
                  / /| |/ / / / / / / / / / /_/ / / / /  |/ /\__ \ 
                 / ___ / /_/ / / / / /_/ / _, _/ /_/ / /|  /___/ / 
                /_/  |_\____/ /_/  \____/_/ |_|\____/_/ |_//____/
_________________________________________________________________________________`n
"@

$AppFName = "Autoruns"
$AppFDescription = "Scheduled tasks/persistence check" 
    $AppFFolder = "Autoruns"
        # URLs
        $AppFURLMain = "https://live.sysinternals.com/autoruns.exe"
        $AppFURLMirror = "https://github.com/resv/THC-MIRROR-APPS/raw/main/Autoruns/autoruns.exe"
           
    $AppFHashMain = "F41051697B220757F3612ECD00749B952CE7BCAADD9DC782D79EF0338E45C3B6"
    $AppFHashMirror = "F41051697B220757F3612ECD00749B952CE7BCAADD9DC782D79EF0338E45C3B6"

    # VARIABLES F - Status notifications
    $StatusFDetectedExisting = ">>> [ Detected existing $AppFName files in $UserDesktopPath\$ParentFolder\$AppFFolder ]`n"
    $StatusFRemoveExisting = ">>> [ Removed existing $AppFName files in $UserDesktopPath\$ParentFolder\$AppFFolder ]`n"
    $StatusFCreatedAppFFolder = ">>>> [ Adding new directory $UserDesktopPath\$ParentFolder\$AppFFolder ]`n"
    $StatusFChangedDirToAppFFolder = ">>>>> [ Changed working directory to $UserDesktopPath\$ParentFolder\$AppFFolder ]`n"
    $StatusFDownloadApp = ">>>>>> [ Downloading `"$AppFName.exe`" ]`n"
    $StatusFHashCheck = ">>>>>>> [ Checking hash ]`n"
    $StatusFBootUp = ">>>>>>>> [ Booting up `"$AppFName`" ]`n"
    $StatusFReady = ">>>>>>>>> [ $AppFName is Ready for Hunting... ]`n"
    $StatusFWipe = ">>>>>>>>>> [ Wiping $AppFName ]"
    $StatusFCreatedAppFLogFolder = "`n10 [ Adding new directory `"$Hostname-Evtx-Logs`" ]`n"
    $StatusFCreatedAppFImportLogFolder = "`n11 [ Adding new directories $UserDesktopPath\$ParentFolder\Import-Log-Folder ]`n"
    $StatusFExportComplete = "`n12 [ Exported raw logs to $UserDesktopPath\$ParentFolder\$Hostname-Evtx-Logs ]`n"
    #$DeepBlueExecute = ".\DeepBlue.ps1"
    #$LogPathExportFolder = "$UserDesktopPath\$ParentFolder\$Hostname-Evtx-Logs"
    #$LogPathImportFolder = "$UserDesktopPath\$ParentFolder\Import-Log-Folder"

    # AppFMenu
$AppFMenu = @"
`n
         _______[ AUTORUNS MENU ]________
        |                                |
        |    [Wipe] | Wipe Autoruns      |
        |    [Exit] | Exit Hard          |
        |    [Back] | Back to Main Menu  |
        |________________________________|`n `n
"@

function StartAutoruns($Source){   
    #Clear
    clear

    # Make space for download status bar
    Write-Host $StatusLoadingLineBreak

    # Notify Autoruns Source URL and hash based on request
     if ($Source -eq "MAIN SOURCE"){
        Write-Host "[MAIN SOURCE]: " -ForegroundColor Green -NoNewline; Write-Host $AppFURLMain -ForegroundColor Yellow
        Write-Host "    [SHA-256]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppFHashMain}" -ForegroundColor Yellow `n 
    }
    if ($Source -eq "MIRROR SOURCE"){
        Write-Host "[MIRROR SOURCE]: " -ForegroundColor Green -NoNewline; Write-Host $AppFURLMirror -ForegroundColor Yellow
        Write-Host "      [SHA-256]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppFHashMirror}" -ForegroundColor Yellow `n
    }

    # Create the in ParentFolder (Also hiding the Powershell Output)
    $null = new-item -path "$UserDesktopPath" -name $ParentFolder -itemtype directory -Force
    Write-Host $StatusCreatedParentFolder -ForegroundColor Green

    # Change the directory to ParentFolder
    set-location "$UserDesktopPath\$ParentFolder"
    Write-Host $StatusChangedDirToParentFolder -ForegroundColor Green

    # Check existing Autoruns folder, if exist, we delete for a fresh start.
    if (Test-Path .\$AppFName) {
        Write-Host $StatusFDetectedExisting -ForegroundColor Green
        $null = taskkill /F /IM Autoruns.exe /T
        Start-Sleep -Seconds 2
        Remove-Item .\$AppFName -Recurse
        Write-Host $StatusFRemoveExisting -ForegroundColor Green
    }

    # Create new Autoruns Folder, change dir to Autoruns folder
    $null = New-Item -Path .\ -Name "$AppFName" -ItemType "directory" -Force
    Write-Host $StatusFCreatedAppFFolder -ForegroundColor Green
    set-location "$UserDesktopPath\$ParentFolder\$AppFName"
    Write-Host $StatusFChangedDirToAppFFolder -ForegroundColor Green        

    # Check for Download request
    if ($Source -eq "MAIN SOURCE"){
        $global:AppFURLUsed = $AppFURLMain
        $AppFHashUsed = $AppFHashMain
    }
    if ($Source -eq "MIRROR SOURCE"){
        $global:AppFURLUsed = $AppFURLMirror
        $AppFHashUsed = $AppFHashMirror
    }

    # Download zip file from Repo
    Write-Host $StatusFDownloadApp -ForegroundColor Green
    Clear-Variable -Name "Source" -Scope Global
    Invoke-WebRequest -Uri $AppFURLUsed -OutFile .\$AppFName.exe

    # Download Autoruns
    Write-Host $StatusFHashCheck -ForegroundColor Green
    $HashDownload = Get-FileHash .\$AppFName.exe | Select-Object -ExpandProperty Hash
   

        # Hash Diff Allow/Deny Progression    
        if ($AppFHashUsed -eq $HashDownload){
            $AppFHashValid = "True"
            Write-Host "  [EXPECTED]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppFHashUsed}" -ForegroundColor Green
            Write-Host "[DOWNLOADED]: " -ForegroundColor Green -NoNewline; Write-Host "{$HashDownload}" -ForegroundColor Green
            Write-Host "              |------------------------ [ HASH VALID ] ------------------------|`n" -ForegroundColor Yellow
        }
        else {
            $AppFHashValid = "False"
            Write-Host "  [EXPECTED]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppFHashUsed}" -ForegroundColor Green
            Write-Host "[DOWNLOADED]: " -ForegroundColor Green -NoNewline; Write-Host "{$HashDownload}" -ForegroundColor Red
            Write-Host "              |---------------------- [ HASH INVALID ] ----------------------|`n" -ForegroundColor Red
            Write-Host "Hash INVALID, URL possibly hijacked or updated. Removed $AppFName.exe, use MIRROR SOURCE for saftey." -ForegroundColor Red
            set-location "$UserDesktopPath\$ParentFolder"
            Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppFFolder"
            Read-Host "Press any key to return to the main menu"
        }

        if ($AppFHashValid -eq "True"){
        # Change the directory to AppFName
        set-location "$UserDesktopPath\$ParentFolder\$AppFFolder"
        $HealthCheck = "True"
        Write-Host $StatusFBootUp -ForegroundColor Green
        Invoke-Expression .\$AppFName.exe
        Write-Host $StatusFReady -ForegroundColor Cyan
        AppFMenuMain
        }

        if ($AppFHashValid -eq "False"){
        # Exit back to main menu
        Show-Menu
        }
}

#AppF Autoruns main menu
function AppFMenuMain{      
    do
    {  
        $selectionAppF = Read-Host $BannerF $AppFmenu "$AppFName main menu, waiting for your input"
        switch ($selectionAppF)
        {
            'Wipe' {
                AppFWipe
                Show-Menu
            }
            'Exit' {
                ExitHard
            }
            'Back' {
                clear
                Show-Menu
            }
            '' {
            clear
            AppFMenuMain
            }
        }
    }
    until ($selectionAppF -eq 'Wipe'-or $selectionAppF -eq 'Back' -or $selectionAppF -eq '')
}
        
# Wipe AutoRuns (Different format due to exe)
function AppFWipe {
    do
    {
    # Confirm user, then implement
    $selectionAppFWipe = Read-Host "Are you sure you want to close & wipe $AppFName (Y/N)"
    switch ($selectionAppFWipe)
    {
        'Y' {
            if (Test-Path "$UserDesktopPath\$ParentFolder\$AppFFolder") {
                Write-Host $StatusFWipe`n
                Write-Host $StatusWipeReminder -ForegroundColor DarkMagenta -Background Yellow
                set-location "$UserDesktopPath\$ParentFolder"
                $null = taskkill /F /IM Autoruns.exe /T  
                Start-Sleep -Seconds 2
                Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppFFolder"
                }
        } 
        'N' {
            clear
            AppFMenuMain
        }
        '' {
            AppFWipe
        }
    }
 }
until ($selectionAppFWipe -eq 'Y' -or $selectionAppFWipe -eq 'N' -or $selectionAppFWipe -eq '')
}
 

# VARIABLES - AppG (ProcMon) -----------------------------------------------------------------------------------------------------------------------------------------------------
$BannerG = @"
_________________________________________________________________________________
                  ____
                 / __ \_________  _________ ___  ____  ____ 
                / /_/ / ___/ __ \/ ___/ __ `__ \/ __ \/ __ \
               / ____/ /  / /_/ / /__/ / / / / / /_/ / / / /
              /_/   /_/   \____/\___/_/ /_/ /_/\____/_/ /_/ 
_________________________________________________________________________________`n
"@                     
$AppGName = "Procmon"
$AppGDescription = "Process Monitor"

$AppGFolder = "Procmon"
        # URLs
        $AppGURLMain = "https://live.sysinternals.com/Procmon.exe"
        $AppGURLMirror = "https://github.com/resv/THC-MIRROR-APPS/raw/main/Procmon/Procmon.exe"
           
    $AppGHashMain = "CFAC057C0C811CAA0FFA8581B7E7E7A2B1C6F3CE8A2EC1D05151A0A2B7DD173E"
    $AppGHashMirror = "CFAC057C0C811CAA0FFA8581B7E7E7A2B1C6F3CE8A2EC1D05151A0A2B7DD173E"

    # VARIABLES G - Status notifications
    $StatusGDetectedExisting = ">>> [ Detected existing $AppGName files in $UserDesktopPath\$ParentFolder\$AppGFolder ]`n"
    $StatusGRemoveExisting = ">>> [ Removed existing $AppGName files in $UserDesktopPath\$ParentFolder\$AppGFolder ]`n"
    $StatusGCreatedAppFFolder = ">>>> [ Adding new directory $UserDesktopPath\$ParentFolder\$AppGFolder ]`n"
    $StatusGChangedDirToAppFFolder = ">>>>> [ Changed working directory to $UserDesktopPath\$ParentFolder\$AppGFolder ]`n"
    $StatusGDownloadApp = ">>>>>> [ Downloading `"$AppGName.exe`" ]`n"
    $StatusGHashCheck = ">>>>>>> [ Checking hash ]`n"
    $StatusGBootUp = ">>>>>>>> [ Booting up `"$AppGName`" ]`n"
    $StatusGReady = ">>>>>>>>> [ $AppGName is Ready for Hunting... ]`n"
    $StatusGWipe = ">>>>>>>>>> [ Wiping $AppGName ]"

# AppGMenu
$AppGMenu = @"
`n
         ________[ Procmon MENU ]________
        |                                |
        |    [Wipe] | Wipe Procmon     |
        |    [Exit] | Exit Hard          |
        |    [Back] | Back to Main Menu  |
        |________________________________|`n `n
"@

function StartProcmon($Source){   
    #Clear
    clear

    # Make space for download status bar
    Write-Host $StatusLoadingLineBreak

    # Notify Procmon Source URL and hash based on request
     if ($Source -eq "MAIN SOURCE"){
        Write-Host "[MAIN SOURCE]: " -ForegroundColor Green -NoNewline; Write-Host $AppGURLMain -ForegroundColor Yellow
        Write-Host "    [SHA-256]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppGHashMain}" -ForegroundColor Yellow `n 
    }
    if ($Source -eq "MIRROR SOURCE"){
        Write-Host "[MIRROR SOURCE]: " -ForegroundColor Green -NoNewline; Write-Host $AppGURLMirror -ForegroundColor Yellow
        Write-Host "      [SHA-256]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppGHashMirror}" -ForegroundColor Yellow `n
    }

    # Create the in ParentFolder (Also hiding the Powershell Output)
    $null = new-item -path "$UserDesktopPath" -name $ParentFolder -itemtype directory -Force
    Write-Host $StatusCreatedParentFolder -ForegroundColor Green

    # Change the directory to ParentFolder
    set-location "$UserDesktopPath\$ParentFolder"
    Write-Host $StatusChangedDirToParentFolder -ForegroundColor Green

    # Check existing Procmon folder, if exist, we delete for a fresh start.
    if (Test-Path .\$AppGName) {
        Write-Host $StatusGDetectedExisting -ForegroundColor Green
        $null = taskkill /F /IM Procmon.exe /T
        Start-Sleep -Seconds 2
        Remove-Item .\$AppGName -Recurse
        Write-Host $StatusGRemoveExisting -ForegroundColor Green
    }

    # Create new Procmon Folder, change dir to Promon folder
    $null = New-Item -Path .\ -Name "$AppGName" -ItemType "directory" -Force
    Write-Host $StatusGCreatedAppFFolder -ForegroundColor Green
    set-location "$UserDesktopPath\$ParentFolder\$AppGName"
    Write-Host $StatusFChangedDirToAppGFolder -ForegroundColor Green        

    # Check for Download request
    if ($Source -eq "MAIN SOURCE"){
        $global:AppGURLUsed = $AppGURLMain
        $AppGHashUsed = $AppGHashMain
    }
    if ($Source -eq "MIRROR SOURCE"){
        $global:AppGURLUsed = $AppGURLMirror
        $AppGHashUsed = $AppGHashMirror
    }

    # Download zip file from Repo
    Write-Host $StatusGDownloadApp -ForegroundColor Green
    Clear-Variable -Name "Source" -Scope Global
    Invoke-WebRequest -Uri $AppGURLUsed -OutFile .\$AppGName.exe

    # Download Procmon
    Write-Host $StatusGHashCheck -ForegroundColor Green
    $HashDownload = Get-FileHash .\$AppGName.exe | Select-Object -ExpandProperty Hash
   

        # Hash Diff Allow/Deny Progression    
        if ($AppGHashUsed -eq $HashDownload){
            $AppGHashValid = "True"
            Write-Host "  [EXPECTED]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppGHashUsed}" -ForegroundColor Green
            Write-Host "[DOWNLOADED]: " -ForegroundColor Green -NoNewline; Write-Host "{$HashDownload}" -ForegroundColor Green
            Write-Host "              |------------------------ [ HASH VALID ] ------------------------|`n" -ForegroundColor Yellow
        }
        else {
            $AppFHashValid = "False"
            Write-Host "  [EXPECTED]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppGHashUsed}" -ForegroundColor Green
            Write-Host "[DOWNLOADED]: " -ForegroundColor Green -NoNewline; Write-Host "{$HashDownload}" -ForegroundColor Red
            Write-Host "              |---------------------- [ HASH INVALID ] ----------------------|`n" -ForegroundColor Red
            Write-Host "Hash INVALID, URL possibly hijacked or updated. Removed $AppGName.exe, use MIRROR SOURCE for saftey." -ForegroundColor Red
            set-location "$UserDesktopPath\$ParentFolder"
            Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppGFolder"
            Read-Host "Press any key to return to the main menu"
        }

        if ($AppGHashValid -eq "True"){
        # Change the directory to AppGName
        set-location "$UserDesktopPath\$ParentFolder\$AppGFolder"
        $HealthCheck = "True"
        Write-Host $StatusGBootUp -ForegroundColor Green
        Invoke-Expression .\$AppGName.exe
        Write-Host $StatusGReady -ForegroundColor Cyan
        AppGMenuMain
        }

        if ($AppGHashValid -eq "False"){
        # Exit back to main menu
        Show-Menu
        }
}

#AppG Procmon main menu
function AppGMenuMain{      
    do
    {  
        $selectionAppG = Read-Host $BannerG $AppGmenu "$AppGName main menu, waiting for your input"
        switch ($selectionAppG)
        {
            'Wipe' {
                AppGWipe
                Show-Menu
            }
            'Exit' {
                ExitHard
            }
            'Back' {
                clear
                Show-Menu
            }
            '' {
            clear
            AppGMenuMain
            }
        }
    }
    until ($selectionAppG -eq 'Wipe'-or $selectionAppG -eq 'Back' -or $selectionAppG -eq '')
}
        
# Wipe Procmon (Different format due to exe)
function AppGWipe {
    do
    {
    # Confirm user, then implement
    $selectionAppGWipe = Read-Host "Are you sure you want to close & wipe $AppGName (Y/N)"
    switch ($selectionAppGWipe)
    {
        'Y' {
            if (Test-Path "$UserDesktopPath\$ParentFolder\$AppGFolder") {
                Write-Host $StatusGWipe`n
                Write-Host $StatusWipeReminder -ForegroundColor DarkMagenta -Background Yellow
                set-location "$UserDesktopPath\$ParentFolder"
                $null = taskkill /F /IM Procmon.exe /T  
                Start-Sleep -Seconds 2
                Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppGFolder"
                }
        } 
        'N' {
            clear
            AppGMenuMain
        }
        '' {
            AppGWipe
        }
    }
 }
until ($selectionAppGWipe -eq 'Y' -or $selectionAppGWipe -eq 'N' -or $selectionAppGWipe -eq '')
}                         


# VARIABLES - AppX (More Info & Contact)
$BannerX = @"
_________________________________________________________________________________
                   __________  _   ___________   ____________
                  / ____/ __ \/ | / /_  __/   | / ____/_  __/
                 / /   / / / /  |/ / / / / /| |/ /     / /   
                / /___/ /_/ / /|  / / / / ___ / /___  / /    
                \____/\____/_/ |_/ /_/ /_/  |_\____/ /_/
_________________________________________________________________________________`n
"@
$AppXName = "Contact"
$AppXDescription = "More Info & Contact"
$AppXVersion = "Alpha 1.0"
$AppxReleaseDate = "6/3/24"
$AppXNotes = @"
All mirrors are direct copies from official sources and hosted on my github. 
Use a mirror if the main source is down or if they have updated their APP/URL`n
"@

$AppXConactInfo= @" 
     ___________________[ ADAM KIM ]_____________________
    |                                                    |
    | [Linkedin] https://www.linkedin.com/in/adamkim456/ |
    | [Discord]  https://discord.gg/HXNprdRD             |
    | [GitHub]   https://github.com/resv                 |
    | [Email]    info@atomkim.com                        |
    |____________________________________________________|`n
"@

$AppXCreditsInfo= @" 
     ____________________[ CREDITS ]________________________
    |                                                       |
    | [DeepBlueCLI] Eric Conrad https://www.ericconrad.com/ |
    | [Sysmon] Microsoft Sysinternals                       |  
    | [Autoruns] Microsoft Sysinternals                     |
    | [Powershell] Microsoft Sysinternals                   |
    |_______________________________________________________|`n
"@

function AppXShowContact {
    Write-Host $BannerX
    Write-Host $StatusBlankSpace [ $AppXVersion $AppXReleaseDate ] `n 
    Write-Host $AppXNotes -ForegroundColor Yellow
    Write-Host $AppXConactInfo -ForegroundColor Cyan
    Write-Host $AppXCreditsInfo -ForegroundColor DarkGray
}

# VARIABLES - AppY (Wipe THC from endpoint) ------------------------------------------------------------------------------------------------------------------------------------------------------------------
$AppYName = "Wipe THC & Exit"
$AppYDescription = "Close, wipe, & exit THC"
$AppYCanQuit = "False"
$StatusYWipe = ">>>>>>>>>> [ Wiping THC Folder ]"
$StatusYWipeComplete = ">>>>>>>>>> [ Success, THC.ps1 needs manual deletion ]"
$StatusYAppState = ""
$StatusYError = ">>>>>>>>>> [ Something went wrong with $StatusAppYState, something holding ownership? ]"

function WipeTHC {
    do
    {
    # Confirm Wipe with user
    $selectionWipeTHC = Read-Host "Are you sure you want wipe THC (Y/N)"
    switch ($selectionWipeTHC)
    {
        'Y' {
            # Closes AppF - If exists, we set state to AppF, if wipe is successful, we reset state and progress to next if.
            if (Test-Path "$UserDesktopPath\$ParentFolder\$AppFFolder") {
                $StatusYAppState = "$AppFName"
                Write-Host "`n$StatusFWipe"
                set-location "$UserDesktopPath\$ParentFolder"
                $null = taskkill /F /IM Autoruns.exe /T  
                Start-Sleep -Seconds 2
                Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppFFolder"
                $StatusYAppState = ""
            }
            # Remove ParentFolder - If exists, we set state to ParentFolder, if wipe is successful, we reset state and progress to next if.
            if (Test-Path "$UserDesktopPath\$ParentFolder") {
                $StatusYAppState = "$ParentFolder"
                Write-Host "$StatusYWipe"
                set-location "$UserDesktopPath"
                Remove-Item "$UserDesktopPath\$ParentFolder" -Recurse -Force
                $StatusYAppState = ""
            }
            # Condition of state satisfied? - If state is blank, all wipes are successful, we can quit.
            if ($StatusYAppState -eq ""){
                Write-Host $StatusYWipeComplete
                [System.Environment]::Exit(0)
            }
            # Condition NOT satisfied to quit, display state of where error occurred.
            if ($StatusYAppState -ne ""){
                Write-Host $StatusYError
                pause
            }
        }
        'N' {
            Show-Menu
            return
        }
    }
 }
 until ($selection -eq 'N')
}

# VARIABLES - AppZ -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
$AppZName = "Hard Exit"
$AppZDescription = "Exit THC and close shell"
$AppZExitingNotification = "`n`n >>>>>>>>>>>>> Exiting, don't forget to wipe :)`n`n"
$ExitHard = "[System.Environment]::Exit(0)"

function ExitHard{
    Write-Host $AppZExitingNotification -ForegroundColor Yellow
    [System.Environment]::Exit(0)
}

# MainMenu ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
$MenuMain = @" 
       [*] Double letter will use mirror if main source is down `n
 [ WORKING ]  [A] $AppAName - $AppADescription
             [*B] $AppBName - $AppBDescription 
 [ WORKING ] [*C] $AppCName - $AppCDescription 
              [D] $AppDName - $AppDDescription 
 [ WORKING ]  [E] $AppEName - $AppEDescription
 [ WORKING ] [*F] $AppFName - $AppFDescription
              [G] $AppGName - $AppGDescription 
 [ WORKING ]  [X] $AppXName - $AppXDescription
 [ WORKING ]  [Y] $AppYName - $AppYDescription
 [ WORKING ]  [Z] $AppZName - $AppZDescription `n
"@


# Execution starts here:
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
function Show-Menu {
    Clear-Host
    Write-Host $Banner1of4 
    Write-Host $Banner2of4 -ForegroundColor Yellow
    Write-Host $Banner3of4 -ForegroundColor Cyan
    Write-Host $Banner4of4 
    Write-Host $MenuMain
}
do
 {
    Show-Menu
    $selection = Read-Host "Waiting for your input"
    switch ($selection)
    {
        'A' {
        HostInfo
        } 
        'B' {
        'You chose option #B'
        } 
        'C' {
        $global:Source = "MAIN SOURCE"
        StartDBCLI($Source)
        } 
        'CC' {
        $global:Source = "MIRROR SOURCE"
        StartDBCLI($Source)
        }
        'D' {
        $global:Source = "MAIN SOURCE"
        StartRemoteAccess($Source)
        }
        'DD' {
        $global:Source = "MIRROR SOURCE"
        StartRemoteAccess($Source)
        }    
        'E' {
        StartEDR
        } 
        'F' {
        $global:Source = "MAIN SOURCE"
        StartAutoruns($Source)
        }
        'FF'{
        $global:Source = "MIRROR SOURCE"
        StartAutoruns($Source)
        }
        'G' {
        $global:Source = "MAIN SOURCE"
        StartProcMon($Source)
        }
        'GG'{
        $global:Source = "MIRROR SOURCE"
        StartProMon($Source)
        }
        'X' {
            Clear-Host
            AppXShowContact
            pause    
        }
        'Y' {
        WipeTHC
        }
        'Z' {
        ExitHard
        }
        '' {
        Show-Menu
        }
    }
 }
 until ($selection -eq 'zz')

