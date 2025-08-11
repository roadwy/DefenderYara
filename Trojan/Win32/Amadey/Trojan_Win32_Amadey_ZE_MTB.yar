
rule Trojan_Win32_Amadey_ZE_MTB{
	meta:
		description = "Trojan:Win32/Amadey.ZE!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5b 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 49 00 4f 00 2e 00 44 00 72 00 69 00 76 00 65 00 49 00 6e 00 66 00 6f 00 5d 00 3a 00 3a 00 47 00 65 00 74 00 44 00 72 00 69 00 76 00 65 00 73 00 28 00 } //1 [System.IO.DriveInfo]::GetDrives(
		$a_00_1 = {46 00 6f 00 72 00 45 00 61 00 63 00 68 00 2d 00 4f 00 62 00 6a 00 65 00 63 00 } //1 ForEach-Objec
		$a_00_2 = {41 00 64 00 64 00 2d 00 4d 00 70 00 50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 45 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 50 00 61 00 74 00 68 00 20 00 24 00 } //1 Add-MpPreference -ExclusionPath $
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}