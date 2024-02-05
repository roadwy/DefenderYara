
rule Trojan_Win32_Injuke_AR_MTB{
	meta:
		description = "Trojan:Win32/Injuke.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 d0 01 d8 05 88 00 00 00 8b 00 69 d9 8c 00 00 00 01 da 33 3a 89 e2 89 7a } //01 00 
		$a_01_1 = {8b 04 24 8b 4c 24 08 8a 14 01 8b 74 24 04 88 14 06 83 c0 01 8b 7c 24 0c 39 f8 89 04 24 75 e1 } //00 00 
	condition:
		any of ($a_*)
 
}