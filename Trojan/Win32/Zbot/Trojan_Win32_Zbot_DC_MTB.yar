
rule Trojan_Win32_Zbot_DC_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {43 3a 5c 54 45 4d 50 5c 66 63 62 6e 61 66 2e 65 78 65 } //C:\TEMP\fcbnaf.exe  01 00 
		$a_81_1 = {68 75 79 6f 6e 74 6f 70 2e 63 6f 6d } //01 00 
		$a_80_2 = {6e 64 64 6b 6a 65 2e 65 78 65 } //nddkje.exe  01 00 
		$a_80_3 = {61 67 6f 72 70 2e 65 78 65 } //agorp.exe  01 00 
		$a_80_4 = {55 70 64 61 74 65 73 20 64 6f 77 6e 6c 6f 61 64 65 72 } //Updates downloader  00 00 
	condition:
		any of ($a_*)
 
}