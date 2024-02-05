
rule Trojan_Win32_Downloader_AC_MTB{
	meta:
		description = "Trojan:Win32/Downloader.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 6a 72 74 75 62 6c 41 6c 57 6f 63 } //01 00 
		$a_01_1 = {47 65 74 3e 6f 64 75 57 65 48 61 6d 64 6c 65 } //01 00 
		$a_80_2 = {61 73 77 43 68 4c 69 63 2e 65 78 65 } //aswChLic.exe  01 00 
		$a_01_3 = {40 72 65 61 4f 65 46 69 2f 65 41 } //01 00 
		$a_01_4 = {74 46 69 2f 65 50 6f 2a 6e 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}