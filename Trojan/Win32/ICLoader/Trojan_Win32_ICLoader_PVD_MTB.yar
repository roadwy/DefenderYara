
rule Trojan_Win32_ICLoader_PVD_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.PVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {31 7c 24 10 8b f5 c1 ee 05 03 74 24 34 81 3d 90 01 04 b4 11 00 00 75 90 09 0a 00 c7 05 90 00 } //02 00 
		$a_02_1 = {8b 45 08 8d 34 07 e8 90 01 04 30 06 83 65 fc 00 c1 eb 09 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}