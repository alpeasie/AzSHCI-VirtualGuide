configuration AzSHCIHost
{
    param ( 
    #[Parameter(Mandatory)]
    [System.Management.Automation.PSCredential]$Admincreds,
    [String]$targetDrive = "D",
    [String]$targetVMPath = "$targetDrive" + ":\VMs",
    #[String]$build_source="https://github.com/microsoft/AzStackHCISandbox/raw/main/Sandbox/Sandbox.zip",
    [String]$predeploy_source="https://raw.githubusercontent.com/alpeasie/AzSHCI-VirtualGuide/main/Deployment/PostDSC/PrepHostForDeployment.ps1",
    [String]$server2019_uri="https://aka.ms/AAbclsv",
    [String]$wacUri = "https://aka.ms/wacdownload"
    )

    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'xCredSSP'
    Import-DscResource -ModuleName 'DSCR_Shortcut'
    Import-DscResource -ModuleName 'cChoco'
    
  
    # [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($Admincreds.UserName)", $Admincreds.Password)

    # $ipConfig = (Get-NetAdapter -Physical | Where-Object { $_.InterfaceDescription -like "*Hyper-V*" } | Get-NetIPConfiguration | Where-Object IPv4DefaultGateway)
    # $netAdapters = Get-NetAdapter -Name ($ipConfig.InterfaceAlias) | Select-Object -First 1
    # $InterfaceAlias = $($netAdapters.Name)

    Node localhost
    {
        LocalConfigurationManager {
            RebootNodeIfNeeded = $true
            ActionAfterReboot  = 'ContinueConfiguration'
            ConfigurationMode  = 'ApplyOnly'
        }

        WindowsFeature Hyper-V {
            Ensure = 'Present'
            Name = "Hyper-V"
            IncludeAllSubFeature = $true
        }
        
        WindowsFeature Hyper-V-PowerShell {
            Ensure = 'Present'
            Name='Hyper-V-PowerShell'
            IncludeAllSubFeature = $true
        }

        WindowsFeature Hyper-V-Manager {
            Ensure = 'Present'
            Name='Hyper-V-Tools'
            IncludeAllSubFeature = $true
        }    

        File "VMfolder" {
            Type            = 'Directory'
            DestinationPath = "$targetVMPath"
            DependsOn       = "[Script]FormatDisk"
            
        }
    
        File "HCI" {
            Type            = 'Directory'
            DestinationPath = "$env:SystemDrive\HCI"
            DependsOn       = "[Script]FormatDisk"
            
        }

        File "VHDs" {
            Type            = 'Directory'
            DestinationPath = "$env:SystemDrive\VHDs"
            DependsOn       = "[Script]FormatDisk"
            
        }

        File "Apps" {
            Type            = 'Directory'
            DestinationPath = "$env:SystemDrive\Apps"
            DependsOn       = "[Script]FormatDisk"
            
        }

        xRemoteFile "Server2019VHD"{
            uri=$server2019_uri
            DestinationPath="$env:SystemDrive\VHDs\GUI.vhdx"
            DependsOn="[File]VHDs"
        }
   
        # Uncomment when HCI iso is public 
        # xRemoteFile "ASHCIVHD"{
        #     uri=$ashci_21h2
        #     DestinationPath="$env:SystemDrive\AzHCIVHDs\AZSHCI.vhdx"
        #     DependsOn="[File]ASHCIBuildScripts"
        # }
   
        xRemoteFile "ASHCIBuildScripts"{
            uri=$predeploy_source
            DestinationPath="$env:SystemDrive\HCI\PrepHostForDeployment.ps1"
            DependsOn="[File]HCI"
        }


        # Uncomment if you need a whole folder, not just a script
        # xRemoteFile "ASHCIBuildScripts"{
        #     uri=$build_source
        #     DestinationPath="$env:SystemDrive\HCI\Deploy.zip"
        #     DependsOn="[File]Deploy"
        # }

        # Archive "ASHCIBuildScripts" {
        #     Path="$env:SystemDrive\HCI\Deploy.zip"
        #     Destination="$env:SystemDrive\HCI\Deploy"
        #     DependsOn="[xRemoteFile]ASHCIBuildScripts"

        # }

        # cShortcut "BuildScript" {
        #     Path="C:\Users\Public\Desktop\PrepHostForDeployment.lnk"
        #     Target="C:\HCI\Deployment\PostDSC\PrepHostForDeployment.ps1"
        #     WorkingDirectory="C:\HCI\Deployment"
        #     Icon='shell32.dll,277'
        #     DependsOn="[xRemoteFile]ASHCIBuildScripts"

        # }

        xRemoteFile "WAC_Source"{
            uri=$wacURI
            DestinationPath="$env:SystemDrive\Apps\WindowsAdminCenter.msi"
            DependsOn="[File]Apps"
        }

        # cShortcut "Wac Shortcut"
        # {
        #     Path      = 'C:\Users\Public\Desktop\Windows Admin Center.lnk'
        #     Target    = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
        #     Arguments = "https://$env:computerName"
        #     Icon      = 'shell32.dll,34'
        # }

        #### CREATE STORAGE SPACES V: & VM FOLDER ####

        Script StoragePool {
            SetScript  = {
                New-StoragePool -FriendlyName AzSHCIPool -StorageSubSystemFriendlyName '*storage*' -PhysicalDisks (Get-PhysicalDisk -CanPool $true)
            }
            TestScript = {
                (Get-StoragePool -ErrorAction SilentlyContinue -FriendlyName AzSHCIPool).OperationalStatus -eq 'OK'
            }
            GetScript  = {
                @{Ensure = if ((Get-StoragePool -FriendlyName AzSHCIPool).OperationalStatus -eq 'OK') { 'Present' } Else { 'Absent' } }
            }
        }
        Script VirtualDisk {
            SetScript  = {
                $disks = Get-StoragePool -FriendlyName AzSHCIPool -IsPrimordial $False | Get-PhysicalDisk
                $diskNum = $disks.Count
                New-VirtualDisk -StoragePoolFriendlyName AzSHCIPool -FriendlyName AzSHCIDisk -ResiliencySettingName Simple -NumberOfColumns $diskNum -UseMaximumSize
            }
            TestScript = {
                (Get-VirtualDisk -ErrorAction SilentlyContinue -FriendlyName AzSHCIDisk).OperationalStatus -eq 'OK'
            }
            GetScript  = {
                @{Ensure = if ((Get-VirtualDisk -FriendlyName AzSHCIDisk).OperationalStatus -eq 'OK') { 'Present' } Else { 'Absent' } }
            }
            DependsOn  = "[Script]StoragePool"
        }
        Script FormatDisk {
            SetScript  = {
                $vDisk = Get-VirtualDisk -FriendlyName AzSHCIDisk
                if ($vDisk | Get-Disk | Where-Object PartitionStyle -eq 'raw') {
                    $vDisk | Get-Disk | Initialize-Disk -Passthru | New-Partition -DriveLetter $Using:targetDrive -UseMaximumSize | Format-Volume -NewFileSystemLabel AzSHCIData -AllocationUnitSize 64KB -FileSystem NTFS
                }
                elseif ($vDisk | Get-Disk | Where-Object PartitionStyle -eq 'GPT') {
                    $vDisk | Get-Disk | New-Partition -DriveLetter $Using:targetDrive -UseMaximumSize | Format-Volume -NewFileSystemLabel AzSHCIData -AllocationUnitSize 64KB -FileSystem NTFS
                }
            }
            TestScript = { 
                (Get-Volume -ErrorAction SilentlyContinue -FileSystemLabel AzSHCIData).FileSystem -eq 'NTFS'
            }
            GetScript  = {
                @{Ensure = if ((Get-Volume -FileSystemLabel AzSHCIData).FileSystem -eq 'NTFS') { 'Present' } Else { 'Absent' } }
            }
            DependsOn  = "[Script]VirtualDisk"
        }


        #### REGISTRY & SCHEDULED TASK TWEAKS ####

        Registry "Disable Internet Explorer ESC for Admin" {
            Key       = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
            Ensure    = 'Present'
            ValueName = "IsInstalled"
            ValueData = "0"
            ValueType = "Dword"
        }

        Registry "Disable Internet Explorer ESC for User" {
            Key       = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
            Ensure    = 'Present'
            ValueName = "IsInstalled"
            ValueData = "0"
            ValueType = "Dword"
        }
        
        Registry "Disable Server Manager WAC Prompt" {
            Key       = "HKLM:\SOFTWARE\Microsoft\ServerManager"
            Ensure    = 'Present'
            ValueName = "DoNotPopWACConsoleAtSMLaunch"
            ValueData = "1"
            ValueType = "Dword"
        }

        Registry "Disable Network Profile Prompt" {
            Key       = 'HKLM:\System\CurrentControlSet\Control\Network\NewNetworkWindowOff'
            Ensure    = 'Present'
            ValueName = ''
        }

        if ($environment -eq "Workgroup") {
            Registry "Set Network Private Profile Default" {
                Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24'
                Ensure    = 'Present'
                ValueName = "Category"
                ValueData = "1"
                ValueType = "Dword"
            }
    
            Registry "SetWorkgroupDomain" {
                Key       = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
                Ensure    = 'Present'
                ValueName = "Domain"
                ValueData = "$DomainName"
                ValueType = "String"
            }
    
            Registry "SetWorkgroupNVDomain" {
                Key       = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
                Ensure    = 'Present'
                ValueName = "NV Domain"
                ValueData = "$DomainName"
                ValueType = "String"
            }
    
            Registry "NewCredSSPKey" {
                Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly'
                Ensure    = 'Present'
                ValueName = ''
            }
    
            Registry "NewCredSSPKey2" {
                Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
                ValueName = 'AllowFreshCredentialsWhenNTLMOnly'
                ValueData = '1'
                ValueType = "Dword"
                DependsOn = "[Registry]NewCredSSPKey"
            }
    
            Registry "NewCredSSPKey3" {
                Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly'
                ValueName = '1'
                ValueData = "*.$DomainName"
                ValueType = "String"
                DependsOn = "[Registry]NewCredSSPKey2"
            }
        }

        # ScheduledTask "Disable Server Manager at Startup" {
        #     TaskName = 'ServerManager'
        #     Enable   = $false
        #     TaskPath = '\Microsoft\Windows\Server Manager'
        # }

        #### STAGE 2h - CONFIGURE CREDSSP & WinRM

        xCredSSP Server {
            Ensure         = "Present"
            Role           = "Server"
            SuppressReboot = $true
        }

        xCredSSP Client {
            Ensure            = "Present"
            Role              = "Client"
            DelegateComputers = "$env:COMPUTERNAME" + ".$DomainName"
            DependsOn         = "[xCredSSP]Server"
            SuppressReboot    = $true
        }

       #### INSTALL CHOCO, DEPLOY EDGE and Shortcuts

        # cChocoInstaller InstallChoco {
        #     InstallDir = "c:\choco"
        # }
            
        # cChocoFeature allowGlobalConfirmation {
        #     FeatureName = "allowGlobalConfirmation"
        #     Ensure      = 'Present'
        #     DependsOn   = '[cChocoInstaller]installChoco'
        # }
        
        # cChocoFeature useRememberedArgumentsForUpgrades {
        #     FeatureName = "useRememberedArgumentsForUpgrades"
        #     Ensure      = 'Present'
        #     DependsOn   = '[cChocoInstaller]installChoco'
        # }
        
        # cChocoPackageInstaller "Install Chromium Edge" {
        #     Name        = 'microsoft-edge'
        #     Ensure      = 'Present'
        #     AutoUpgrade = $true
        #     DependsOn   = '[cChocoInstaller]installChoco'
        # }


    }
}