
rule Trojan_Win32_SmokeLoader_E_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 0c 24 b8 d1 05 00 00 01 04 24 8b 14 24 8a 04 32 8b 0d 90 01 04 88 04 31 81 c4 04 08 00 00 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_SmokeLoader_E_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {03 c7 33 c1 8b ca c1 e9 90 01 01 03 4d f0 89 45 08 33 c8 89 4d 0c 8b 45 0c 01 05 90 01 04 8b 45 0c 29 45 fc 8b 45 fc c1 e0 90 01 01 89 45 08 90 00 } //0a 00 
		$a_03_1 = {6a 73 58 6a 6d 66 a3 90 01 04 58 6a 67 66 a3 90 01 04 58 6a 69 66 a3 90 01 04 58 6a 6c 66 a3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}