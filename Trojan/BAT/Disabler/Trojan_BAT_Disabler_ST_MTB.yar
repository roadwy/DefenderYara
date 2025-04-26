
rule Trojan_BAT_Disabler_ST_MTB{
	meta:
		description = "Trojan:BAT/Disabler.ST!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 45 72 72 6f 72 41 63 74 69 6f 6e 50 72 65 66 65 72 65 6e 63 65 20 3d 20 22 53 69 6c 65 6e 74 6c 79 43 6f 6e 74 69 6e 75 65 22 } //2 $ErrorActionPreference = "SilentlyContinue"
		$a_01_1 = {20 20 20 20 20 20 20 20 57 72 69 74 65 2d 48 6f 73 74 20 22 54 68 69 73 20 69 73 20 61 20 48 79 70 65 72 2d 56 20 56 69 72 74 75 61 6c 20 4d 61 63 68 69 6e 65 20 72 75 6e 6e 69 6e 67 20 6f 6e 20 70 68 79 73 69 63 61 6c 20 68 6f 73 74 20 24 70 68 79 73 69 63 61 6c 48 6f 73 74 22 } //2         Write-Host "This is a Hyper-V Virtual Machine running on physical host $physicalHost"
		$a_01_2 = {20 20 20 20 24 76 6d 77 61 72 65 53 65 72 76 69 63 65 73 20 3d 20 40 28 22 76 6d 64 65 62 75 67 22 2c 20 22 76 6d 6d 6f 75 73 65 22 2c 20 22 56 4d 54 6f 6f 6c 73 22 2c 20 22 56 4d 4d 45 4d 43 54 4c 22 2c 20 22 74 70 61 75 74 6f 63 6f 6e 6e 73 76 63 22 2c 20 22 74 70 76 63 67 61 74 65 77 61 79 22 2c 20 22 76 6d 77 61 72 65 22 2c 20 22 77 6d 63 69 22 2c 20 22 76 6d 78 38 36 22 29 } //2     $vmwareServices = @("vmdebug", "vmmouse", "VMTools", "VMMEMCTL", "tpautoconnsvc", "tpvcgateway", "vmware", "wmci", "vmx86")
		$a_01_3 = {20 20 20 20 24 62 69 6f 73 56 65 72 73 69 6f 6e 20 3d 20 47 65 74 2d 52 65 67 69 73 74 72 79 56 61 6c 75 65 53 74 72 69 6e 67 20 2d 4b 65 79 20 22 48 4b 4c 4d 5c 48 41 52 44 57 41 52 45 5c 44 45 53 43 52 49 50 54 49 4f 4e 5c 53 79 73 74 65 6d 22 20 2d 56 61 6c 75 65 4e 61 6d 65 20 22 53 79 73 74 65 6d 42 69 6f 73 56 65 72 73 69 6f 6e 22 } //2     $biosVersion = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System" -ValueName "SystemBiosVersion"
		$a_01_4 = {49 6e 76 6f 6b 65 2d 53 65 6c 66 52 65 70 6c 69 63 61 74 69 6f 6e } //2 Invoke-SelfReplication
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}