. "C:\Scripts\Convert-WindowsImage.ps1"
Convert-WindowsImage -SourcePath "C:\VHDs\hcios.iso"  `
 -Edition "Azure Stack HCI" `
 -SizeBytes 60GB  `
 -VHDFormat "VHDX"  `
 -DiskLayout "UEFI"  `
 -VHDPath "C:\VHDs\hcios.vhdx"  `
 -isfixed

Write-Verbose "Done converting iso to VHD"

Start-Sleep 5

### Network prep host ####
# Networking config 
$HostSwitchName = "InternalDemo"
$HostAdapterName = "vEthernet (InternalDemo)"
$NatNetworkName = "AzSHCINAT"


Write-Output "done with network config"
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