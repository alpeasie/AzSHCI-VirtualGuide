##### PREP Host Machine for config ###
Set-VMhost -EnableEnhancedSessionMode $True

####### Creds for script ##################
$username = "Administrator"
$Password = "wacTesting1!"
$securePw = ConvertTo-SecureString $Password -AsPlainText -Force
$localCred = New-Object Management.Automation.PSCredential($username, $securePw)


### Convert ASHCI iso to VHD###

. "C\HelperScripts\Convert-WindowsImage.ps1"
Convert-WindowsImage -SourcePath "C:\AzHCIVHDs\hcios.iso"  `
 -Edition "Azure Stack HCI" `
 -SizeBytes 60GB  `
 -VHDFormat "VHDX"  `
 -DiskLayout "UEFI"  `
 -VHDPath "C:\VHDs\hcios.vhdx"  `
 -isfixed

Write-Verbose "Done converting iso to VHD"


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
$vmname = "DC01"

### Create Differencing disk for DC

$parentDisk = "C:\VHDs\GUI.vhdx"
New-VHD -Differencing -ParentPath $parentDisk -Path "V:\VMs\$vmname\Virtual Hard Disks\$vmname.vhdx"


### Create the Domain Controller ###

New-VM `
    -Name $vmname `
    -MemoryStartupBytes 4GB `
    -SwitchName "InternalDemo" `
    -Path "V:\VMs\" `
    -VHDPath "V:\VMs\$vmname\Virtual Hard Disks\$vmname.vhdx" `
    -Generation 2

Set-VMMemory DC01 -DynamicMemoryEnabled $true -MinimumBytes 1GB -StartupBytes 4GB -MaximumBytes 4GB


Start-Sleep -Seconds 5


# INJECT ANSWER FILE


Write-Verbose "Mounting Disk Image and Injecting Answer File into the $vmname VM." 
New-Item -Path "C:\TempBGPMount" -ItemType Directory | Out-Null
Mount-WindowsImage -Path "C:\TempBGPMount" -Index 1 -ImagePath ("V:\VMs\$vmname\Virtual Hard Disks\$vmname.vhdx") | Out-Null

New-Item -Path C:\TempBGPMount\windows -ItemType Directory -Name Panther -Force | Out-Null


$Unattend = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <servicing>
        <package action="configure">
            <assemblyIdentity name="Microsoft-Windows-Foundation-Package" version="10.0.14393.0" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="" />
            <selection name="ADCertificateServicesRole" state="true" />
            <selection name="CertificateServices" state="true" />
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
Dismount-WindowsImage -Path "C:\TempBGPMount" -Save | Out-Null
Remove-Item "C:\TempBGPMount"

#### END ANSWER ####

Write-Verbose "Done dismounting; starting VM" -Verbose

# Start modifying DC VM

Start-VM -Name $VMName      


# Test for the DC01 to be back online and responding
while ((Invoke-Command -VMName DC01 -Credential $localCred {"Test"} -ErrorAction SilentlyContinue) -ne "Test") {
    Start-Sleep -Seconds 1
}
Write-Verbose "DC01 is now online....." -Verbose



# Provide a password for the VM that you set in the previous step
Invoke-Command -VMName "DC01" -Credential $localCred -ScriptBlock {
    # Configure new IP address for DC01 NIC
    New-NetIPAddress -IPAddress "192.168.0.2" -DefaultGateway "192.168.0.1" -InterfaceAlias "Ethernet" -PrefixLength "24" | Out-Null
    Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses ("1.1.1.1")
    $dcIP = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Ethernet" | Select-Object IPAddress
    Write-Verbose "The currently assigned IPv4 address for DC01 is $($dcIP.IPAddress)" -Verbose 
    # Update Hostname to DC01
    #Write-Verbose "Updating Hostname for DC01" -Verbose
    #Rename-Computer -NewName "DC01"
}

Write-Verbose "Rebooting DC01 for hostname change to take effect" -Verbose
Stop-VM -Name DC01
Start-VM -Name DC01

# Test for the DC01 to be back online and responding
while ((Invoke-Command -VMName DC01 -Credential $localCred {"Test"} -ErrorAction SilentlyContinue) -ne "Test") {
    Start-Sleep -Seconds 3
}
Write-Verbose "DC01 is now online..." -Verbose


$domainName = "cosei.com"


# Configure Active Directory on DC01
Invoke-Command -VMName DC01 -Credential $localCred1 -ScriptBlock {
    # Set the Directory Services Restore Mode password
    $DSRMPWord = ConvertTo-SecureString -String "Password01" -AsPlainText -Force
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    Install-ADDSForest `
        -CreateDnsDelegation:$false `
        -DatabasePath "C:\Windows\NTDS" `
        -DomainMode 7 `
        -DomainName "cosei.com" `
        -ForestMode 7 `
        -InstallDns:$true `
        -SafeModeAdministratorPassword $DSRMPWord `
        -LogPath "C:\Windows\NTDS" `
        -NoRebootOnCompletion:$true `
        -SysvolPath "C:\Windows\SYSVOL" `
        -Force:$true
}



Write-Verbose "Rebooting DC01 to finish installing of Active Directory" -Verbose
Stop-VM -Name DC01
Start-Sleep -Seconds 5
Start-VM -Name DC01




while ((Invoke-Command -VMName DC01 -Credential $domainCred {"Test"} -ErrorAction SilentlyContinue) -ne "Test") {
    Start-Sleep -Seconds 3
}
Write-Verbose "DC01 is now online..." -Verbose

Write-Verbose "Setting up HCI OU" -Verbose

### Set up OU ######


$domainName = "cosei.com"
$domainAdmin = "$domainName\administrator"
$Password = "wacTesting1!"
$securePw = ConvertTo-SecureString $Password -AsPlainText -Force
$domainCred = New-Object Management.Automation.PSCredential($domainAdmin, $securePw)

### This is the last block I need to test -- wait till PS gallery is published ####
Invoke-Command -VMName DC01 -Credential $domainCred -ScriptBlock {
    # Set the Directory Services Restore Mode password
    Install-PackageProvider -Name NuGet -Force | Out-Null
    Install-Module -Name HCIAdObjectPreCreation -Repository PSGallery -Force

    $deployAdmin = "AzureAdmin"
    $Password = "wacTesting1!"
    $securePw = ConvertTo-SecureString $Password -AsPlainText -Force
    $deployCred = New-Object Management.Automation.PSCredential($deployAdmin, $securePw)

    Add-KdsRootKey -EffectiveTime ((Get-Date).addhours(-10))
    New-HciAdObjectsPreCreation -Deploy -AsHciDeploymentUserCredential $deployCred -AsHciOUName "OU=contoso,DC=cosei,DC=com" -AsHciPhysicalNodeList @("AZSHCINODE01", "AZSHCINODE02") -DomainFQDN "cosei.com" -AsHciClusterName "cluster1"  -AsHciDeploymentPrefix "hci" 

    
}


Write-Verbose "HCI OU done" -Verbose

Write-Verbose "Deploying node VMs for cluster" -Verbose

 

########## Create node VMs  ###########

$azsHostCount = 2

for ($i = 1; $i -lt $azsHostCount + 1; $i++) {
    $suffix = '{0:D2}' -f $i
    $vmname = $("AZSHCINODE" + $suffix)

    $parentDisk = 'C:\VHDs\hcios.vhdx'


    New-VHD -Differencing -ParentPath $parentDisk -Path "V:\VMs\$vmname\Virtual Hard Disks\$vmname.vhdx"

    New-Vm -Name $vmname -MemoryStartupBytes 8GB -VHDPath "V:\VMs\$vmname\Virtual Hard Disks\$vmname.vhdx" -Generation 2 -Path "V:\VMs\$vmname\"

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
    new-VHD -Path "V:\VMs\$vmname\Virtual Hard Disks\data.vhdx" -SizeBytes 127GB 05
    
    # Create the DATA virtual hard disks and attach them
    $dataDrives = 1..3 | ForEach-Object { New-VHD -Path "V:\VMs\$vmname\Virtual Hard Disks\DATA0$_.vhdx" -Dynamic -SizeBytes 100GB }
    $dataDrives | ForEach-Object {
        Add-VMHardDiskDrive -Path $_.path -VMName $vmname
    }


    #Disable time synchronization 
    Get-VMIntegrationService -VMName $vmname |Where-Object {$_.name -like "T*"}|Disable-VMIntegrationService 
    Set-VmProcessor -VmName $vmname -ExposeVirtualizationExtensions $true 


    # Inject Answer File

    Write-Verbose "Mounting Disk Image and Injecting Answer File into the $VMName VM." -Verbose
    New-Item -Path "C:\TempBGPMount" -ItemType Directory | Out-Null
    Mount-WindowsImage -Path "C:\TempBGPMount" -Index 1 -ImagePath ("V:\VMs\$vmname\Virtual Hard Disks\$vmname.vhdx") | Out-Null

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

    Write-Verbose "Enabling Remote Access" -Verbose
    Enable-WindowsOptionalFeature -Path C:\TempBGPMount -FeatureName RasRoutingProtocols -All -LimitAccess | Out-Null
    Enable-WindowsOptionalFeature -Path C:\TempBGPMount -FeatureName RemoteAccessPowerShell -All -LimitAccess | Out-Null


    Write-Verbose "Dismounting Disk Image for $VMName VM." -Verbose
    Dismount-WindowsImage -Path "C:\TempBGPMount" -Save | Out-Null
    Remove-Item "C:\TempBGPMount"


    # Start the VM

    Write-Verbose "Starting $VMName VM." -Verbose
    Start-VM -Name $VMName
    while ((Invoke-Command -VMName $vmname -Credential $localCred {"Test"} -ErrorAction SilentlyContinue) -ne "Test") {
        Start-Sleep -Seconds 1
    }
    Write-Verbose "$VMName is now online....." -Verbose
    Write-Verbose "Assigning IP addresses" -Verbose

    # Set IP addresses on both VMs
    $newIP = ""

    if($VMName -eq "AZSHCINODE01") {
        $newIP = "192.168.0.3"
    } else {
        $newIP = "192.168.0.4"
    }

    # Add IP addresses

    Invoke-Command -VMName $VMName -Credential $localCred -scriptblock {
        # Set Static IP
        New-NetIPAddress -IPAddress "$using:newIP" -DefaultGateway "192.168.0.1" -InterfaceAlias "Ethernet" -PrefixLength "24" | Out-Null
        Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses ("192.168.0.2")
        $nodeIP = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Ethernet" | Select-Object IPAddress
        Write-Verbose "The currently assigned IPv4 address for $using:VMName is $($nodeIP.IPAddress)" -Verbose
    }

    Start-Sleep -Seconds 5

    Write-Verbose "IP address assignment done" -Verbose
    Write-Verbose "Initializing disks on both VMs" -Verbose


    # Initialize disk on both VMs
    Invoke-Command -VMName $VMName -Credential $localCred -scriptblock {
        Set-disk 1 -isOffline $false 
        Set-Disk 1 -isReadOnly $false 
        Initialize-Disk 1 -PartitionStyle GPT 
        New-Partition -DiskNumber 1 -UseMaximumSize 
        Get-Partition -DiskNumber 1 -PartitionNumber 2 | Format-Volume -FileSystem NTFS 
        Get-Partition -DiskNumber 1 -PartitionNumber 2 | Set-Partition -NewDriveLetter D 
    }

    write-verbose "Initialized disk on $Vmname" -Verbose

    # Install Hyper-V on both VMs and enable WinRM
    Invoke-Command -VMName $VMName -Credential $localCred -scriptblock {    
        Write-Verbose "Installing Hyper-V" -Verbose
        Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All

        Write-Verbose "Enabling Windows Remoting"
        $VerbosePreference = "SilentlyContinue" 
        Set-Item WSMan:\localhost\Client\TrustedHosts *  -Confirm:$false -Force
        Enable-PSRemoting | Out-Null
        $VerbosePreference = "Continue" 
        write-verbose "Enabled remoting on VM" -Verbose
        write-verbose "Enabling ICMP" -Verbose
        netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol="icmpv4:8,any" dir=in action=allow

    }
    Start-Sleep -Seconds 5

}


####### Set up seed Node (VM 1) ########


# Copy build to VM

write-verbose "Copying cloud folder to AZSHCINODE01. This will take awhile..." -Verbose
$s = New-PSSession -VMName "AZSHCINODE01" -Credential $localCred
$HCIPath = "C:\Cloud\CloudDeployment"
Copy-Item $HCIPath –Destination "D:\" -ToSession $s -Recurse
write-verbose "Copied cloud folder to D:\ from $HCIPath" -Verbose


# Run cloud deploy tool on VM
write-verbose "Running the bootstrap script on AZSHCINODE01. This will take around 30 minutes to complete" -Verbose
Invoke-Command -VMName "AZSHCINODE01" -Credential $localCred -Command {D:\Cloud\CloudDeployment\Setup\BootstrapCloudDeploymentTool.ps1}
write-verbose "Bootstrap script is done running. You can now start deployment " -Verbose




