
rule Trojan_Win32_Amadey_ZC_MTB{
	meta:
		description = "Trojan:Win32/Amadey.ZC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {4d 00 70 00 50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 45 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 50 00 61 00 74 00 68 00 20 00 40 00 28 00 24 00 65 00 6e 00 76 00 3a 00 55 00 73 00 65 00 72 00 50 00 72 00 6f 00 66 00 69 00 6c 00 65 00 2c 00 20 00 24 00 65 00 6e 00 76 00 3a 00 53 00 79 00 73 00 74 00 65 00 6d 00 44 00 72 00 69 00 76 00 65 00 } //1 MpPreference -ExclusionPath @($env:UserProfile, $env:SystemDrive
		$a_00_1 = {68 00 69 00 64 00 64 00 65 00 6e 00 } //1 hidden
		$a_00_2 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //1 DownloadString
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}