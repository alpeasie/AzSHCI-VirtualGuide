##### PREP Host Machine for config ###
Set-VMhost -EnableEnhancedSessionMode $True

####### Creds for script ##################
$username = "Administrator"
$Password = "wacTesting1!"
$securePw = ConvertTo-SecureString $Password -AsPlainText -Force
$localCred = New-Object Management.Automation.PSCredential($username, $securePw)


### Network prep host ####
# Networking config 
$HostSwitchName = "InternalDemo"
$HostAdapterName = "vEthernet (InternalDemo)"
$NatNetworkName = "AzSHCINAT"

New-VMSwitch -SwitchName $HostSwitchName -SwitchType Internal

$HostIndex = Get-NetAdapter -Name $HostAdapterName | Select-Object -Property ifIndex -ExpandProperty ifIndex

New-NetIPAddress -IPAddress 192.168.0.1 -PrefixLength 24 -InterfaceIndex $HostIndex

# Configure NAT rules
New-NetNat -Name $NatNetworkName -InternalIPInterfaceAddressPrefix 192.168.0.0/24
Add-NetNatStaticMapping -NatName $NatNetworkName -ExternalIPAddress 0.0.0.0 -InternalIPAddress 192.168.0.92 -Protocol TCP -ExternalPort 53389 -InternalPort 3389 
Add-NetNatStaticMapping -NatName $NatNetworkName -ExternalIPAddress 0.0.0.0 -InternalIPAddress 192.168.0.92 -Protocol TCP -ExternalPort 5443 -InternalPort 443 




# Create DC

### Run DC script ###

########## Create node VMs  ###########

$azsHostCount = 2

for ($i = 1; $i -lt $azsHostCount + 1; $i++) {
    $suffix = '{0:D2}' -f $i
    $vmname = $("AZSHCINODE" + $suffix)

    $parentDisk = "C:\Core\Image\ServerHCI.vhdx"

    New-VHD -Differencing -ParentPath $parentDisk -Path "D:\VMs\$vmname\Virtual Hard Disks\$vmname.vhdx"

    New-Vm -Name $vmname -MemoryStartupBytes 8GB -VHDPath "D:\VMs\$vmname\Virtual Hard Disks\$vmname.vhdx" -Generation 2 -Path "D:\VMs\$vmname\"

    #Add second network adapter 
    Add-VmNetworkAdapter -VmName $vmname 

    #Attach both adapters to virtual switch 
    Get-VmNetworkAdapter -VmName $vmname|Connect-VmNetworkAdapter -SwitchName $HostSwitchName
    
    #Enable MAC spoofing on both adapters 
    Get-VmNetworkAdapter -VmName $vmname|Set-VmNetworkAdapter -MacAddressSpoofing On 

    #Enable trunk port (for multi-node deployments only) 
    Get-VmNetworkAdapter -VmName $vmname|Set-VMNetworkAdapterVlan -Trunk -NativeVlanId 0 -AllowedVlanIdList 0-1000 

 
    #Enable TPM 
    Set-VMKeyProtector -NewLocalKeyProtector -VmName $vmname
    Enable-VmTpm -VMName $vmname

    #Change virtual processors to 4 
    Set-VmProcessor -VMName $vmname -Count 4 


    # Create data disk for deployment tool  
    new-VHD -Path "D:\VMs\$vmname\Virtual Hard Disks\data.vhdx" -SizeBytes 127GB 
    Add-VMHardDiskDrive -VMName $vmname -Path "D:\VMs\$vmname\Virtual Hard Disks\data.vhdx" 
    
    # Create the DATA virtual hard disks and attach them
    $dataDrives = 1..3 | ForEach-Object { New-VHD -Path "D:\VMs\$vmname\Virtual Hard Disks\DATA0$_.vhdx" -Dynamic -SizeBytes 100GB }
    $dataDrives | ForEach-Object {
        Add-VMHardDiskDrive -Path $_.path -VMName $vmname
    }


    #Disable time synchronization 
    Get-VMIntegrationService -VMName $vmname |Where-Object {$_.name -like "T*"}|Disable-VMIntegrationService 
    Set-VmProcessor -VmName $vmname -ExposeVirtualizationExtensions $true 


    # Inject Answer File

    Write-Verbose "Mounting Disk Image and Injecting Answer File into the $VMName VM." 
    New-Item -Path "C:\TempBGPMount" -ItemType Directory | Out-Null
    Mount-WindowsImage -Path "C:\TempBGPMount" -Index 1 -ImagePath ("D:\VMs\$vmname\Virtual Hard Disks\$vmname.vhdx") | Out-Null

    New-Item -Path C:\TempBGPMount\windows -ItemType Directory -Name Panther -Force | Out-Null

   

    $Unattend = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
        <servicing>
            <package action="configure">
                <assemblyIdentity name="Microsoft-Windows-Foundation-Package" version="10.0.14393.0" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="" />
                <selection name="RemoteAccessServer" state="true" />
                <selection name="RasRoutingProtocols" state="true" />
            </package>
        </servicing>
        <settings pass="specialize">
            <component name="Networking-MPSSVC-Svc" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <DomainProfile_EnableFirewall>false</DomainProfile_EnableFirewall>
                <PrivateProfile_EnableFirewall>false</PrivateProfile_EnableFirewall>
                <PublicProfile_EnableFirewall>false</PublicProfile_EnableFirewall>
            </component>
            <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <ComputerName>$vmname</ComputerName>
            </component>
            <component name="Microsoft-Windows-TerminalServices-LocalSessionManager" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <fDenyTSConnections>false</fDenyTSConnections>
            </component>
            <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <UserLocale>en-us</UserLocale>
                <UILanguage>en-us</UILanguage>
                <SystemLocale>en-us</SystemLocale>
                <InputLocale>en-us</InputLocale>
            </component>
        </settings>
        <settings pass="oobeSystem">
            <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <OOBE>
                    <HideEULAPage>true</HideEULAPage>
                    <SkipMachineOOBE>true</SkipMachineOOBE>
                    <SkipUserOOBE>true</SkipUserOOBE>
                    <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
                </OOBE>
                <UserAccounts>
                    <AdministratorPassword>
                        <Value>$Password</Value>
                        <PlainText>true</PlainText>
                    </AdministratorPassword>
                </UserAccounts>
            </component>
        </settings>
        <cpi:offlineImage cpi:source="" xmlns:cpi="urn:schemas-microsoft-com:cpi" />
    </unattend>    
"@
  
    Set-Content -Value $Unattend -Path "C:\TempBGPMount\Windows\Panther\Unattend.xml" -Force

    Write-Verbose "Enabling Remote Access"
    Enable-WindowsOptionalFeature -Path C:\TempBGPMount -FeatureName RasRoutingProtocols -All -LimitAccess | Out-Null
    Enable-WindowsOptionalFeature -Path C:\TempBGPMount -FeatureName RemoteAccessPowerShell -All -LimitAccess | Out-Null
    Write-Verbose "Dismounting Disk Image for $VMName VM." 
    Dismount-WindowsImage -Path "C:\TempBGPMount" -Save | Out-Null
    Remove-Item "C:\TempBGPMount"


    # Start the VM

    Write-Verbose "Starting $VMName VM." -Verbose
    Start-VM -Name $VMName
    while ((Invoke-Command -VMName $vmname -Credential $localCred {"Test"} -ErrorAction SilentlyContinue) -ne "Test") {
        Start-Sleep -Seconds 1
    }
    Write-Verbose "$VMName is now online....." -Verbose


    # Set IP addresses on both VMs
    $newIP = ""

    if($VMName -eq "AZSHCINODE01") {
        $newIP = "192.168.0.3"
    } else {
        $newIP = "192.168.0.4"
    }

    # Add IP addresses
    $AssignIP = Invoke-Command -VMName $VMName -Credential $localCred -scriptblock {

        # Set Static IP
        New-NetIPAddress -IPAddress "$using:newIP" -DefaultGateway "192.168.0.1" -InterfaceAlias "Ethernet" -PrefixLength "24" | Out-Null
        Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses ("192.168.0.2")
        $nodeIP = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Ethernet" | Select-Object IPAddress
        Write-Verbose "The currently assigned IPv4 address for $using:VMName is $($nodeIP.IPAddress)" -Verbose
 
    } -AsJob

    $AssignIP | Wait-Job

    Start-Sleep -Seconds 5


    # Initialize disk on both VMs
    Invoke-Command -VMName $VMName -Credential $localCred -scriptblock {
        Set-disk 1 -isOffline $false 
        Set-Disk 1 -isReadOnly $false 
        Initialize-Disk 1 -PartitionStyle GPT 
        New-Partition -DiskNumber 1 -UseMaximumSize 
        Get-Partition -DiskNumber 1 -PartitionNumber 2 | Format-Volume -FileSystem NTFS 
        Get-Partition -DiskNumber 1 -PartitionNumber 2 | Set-Partition -NewDriveLetter D 
    }

    write-verbose "Initialized disk on $Vmname"


    Start-Sleep -Seconds 5

}


####### Set up seed Node (VM 2) ########


# Copy build to VM 2 #  NOTE, might be able to put this in the VM for loop and copy without using local creds, 

write-verbose "Copying cloud folder to $VMName . This will take awhile..."
$s = New-PSSession -VMName "AZSHCINODE02"  -Credential $localCred
$HCIPath = "C:\Core\Cloud\"
Copy-Item $HCIPath –Destination "D:\" -ToSession $s -Recurse

write-verbose "Copied cloud folder to $VMPath at $HCIPath"



############### End of Main SCRIPT ####################

# 1. log in to AZSHCINODE 02 then run the lines of code

# This takes like 30-45 minutes 
cd "D:\Cloud\"
.\BootstrapCloudDeploymentTool.ps1

# Future option - try to remotely run the file and return the status when it's done

# Test for more verbose - doesn't update status 
$seedNodeSession = New-PSSession -VMName "AZSHCINODE02"  -Credential $localCred
$testCommand = Invoke-Command -Session $seedNodeSession -ScriptBlock {powershell "D:\2209CoreSep8\Cloud\BootstrapCloudDeploymentTool.ps1" }
return $testCommand
write-verbose "Cloud deployment tool done"



####### AFTER RUNNIG CLOUD DEPLOYMENT, TRY COPYING AD tool to AD NODE #######

write-verbose "Copying cloud folder to $VMName . This will take awhile..."
$s = New-PSSession -VMName "AZSHCINODE02"  -Credential $localCred
$HCIPath = "C:\Core\Cloud\"
Copy-Item $HCIPath –Destination "D:\" -FromSession $s -Recurse

write-verbose "Copied cloud folder to $VMPath at $HCIPath"




###### #OLLLDDDDDDDD #####################


# Join domain 
for ($i = 1; $i -lt $azsHostCount + 1; $i++) {
    $suffix = '{0:D2}' -f $i
    $vmname = $("AZSHCINODE" + $suffix)

    Invoke-Command -VMName $vmname -Credential $localcred -ScriptBlock {
        Add-Computer -DomainName "azshci.com" -Credential $using:domainCred -Force
    }

    Write-Verbose "Rebooting $vmname for hostname change to take effect" -Verbose
    Stop-VM -Name $vmname
    Start-Sleep -Seconds 5
    Start-VM -Name $vmname

}


Start-Sleep -Seconds 45


# STEPS FOR ALEX BUILD SEP 



# OLD
.\BootstrapCloudDeploymentTool.ps1 -RegistrationSubscriptionID "e98d0648-f21a-417d-8470-db17aab036a7"

# After cloud deploy tool is run, prep AD from seed node (this will change once there is a link to download ADprep)

#Create a Microsoft Key Distribution Service root key on the domain controller to generate group Managed Service Account passwords.

######## Join VMs to Domain  ##########
$domainName = "azshci.com"
$domainAdmin = "$domainName\AzureAdmin"
$Password = "wacTesting1!"
$securePw = ConvertTo-SecureString $Password -AsPlainText -Force
$domainCred = New-Object Management.Automation.PSCredential($domainAdmin, $securePw)

Enter-PSSession -ComputerName 192.168.0.5 -credential $domainCred



Add-KdsRootKey -EffectiveTime ((Get-Date).addhours(-10))

# Cd to CloudDeployment\Prepare and run script
#### NOTE for future, figure out prefix 
cd "C:\CloudDeployment\Prepare"
.\AsHciADArtifactsPreCreationTool.ps1 `
        -AsHciDeploymentUserCredential $domainCred `
        -AsHciOUName "OU=test,DC=azshci,DC=com" `
        -AsHciPhysicalNodeList @("AZSHCINODE01, AZSHCINODE02") `
        -DomainFQDN "azshci.com" `
        -AsHciClusterName "cluster01" `
        -AsHciDeploymentPrefix "hci" `








### #END AD prep 




#### OLD code ######



####### Run script on VM ##############

$SubscriptionID = "e98d0648-f21a-417d-8470-db17aab036a7"
$AzureCred = Get-credential
$AzureCloud="AzureCloud"

# First time, figure out what params are
cd D:\CloudDeployment\Setup 
.\BootstrapCloudDeploymentTool-Internal.ps1

# New builds ask for subscription ID







##### INVALID CODE ##################
# OR, try remotely running the code below 

$domainSession = New-PSSession -VMName "AZSHCINODE02"  -Credential $domainCred
Invoke-Command -Session $domainSession -ScriptBlock {
    powershell "D:\2209CoreSep8\Cloud\BootstrapCloudDeploymentTool.ps1" -RegistrationSubscriptionID "e98d0648-f21a-417d-8470-db17aab036a7"}




## Other shit


Invoke-Command -VMName "AZSHCINODE02" -Credential $localCred -scriptblock {Expand-Archive -Path "D:\Core\Cloud.zip" -DestinationPath "D:\Core\Cloud"}
write-verbose "Done unzipping folder"

Expand-Archive -Path "C:\Users\alpease\Desktop\Builds\Core\Cloud\CloudDeployment_10.2209.0.13.zip" -DestinationPath "C:\Users\alpease\Desktop\Builds\Core\Cloud\"
