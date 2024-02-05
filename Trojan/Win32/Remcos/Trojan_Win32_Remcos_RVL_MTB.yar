
rule Trojan_Win32_Remcos_RVL_MTB{
	meta:
		description = "Trojan:Win32/Remcos.RVL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 52 5a 4c 50 58 44 43 55 4c 51 4a 49 4b 4f 52 49 42 4b 44 42 53 45 } //01 00 
		$a_00_1 = {c7 45 fc da 93 1f 38 33 c0 8b c8 83 e1 03 8a 4c 0d f8 30 4c 05 fc 40 83 f8 04 } //01 00 
		$a_02_2 = {8b c8 83 e1 03 8a 4c 0d f8 30 88 90 01 04 40 3d 05 5c 00 00 72 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}