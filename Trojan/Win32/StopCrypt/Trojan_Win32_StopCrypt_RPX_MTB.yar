
rule Trojan_Win32_StopCrypt_RPX_MTB{
	meta:
		description = "Trojan:Win32/StopCrypt.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 d4 01 45 fc 89 5d f0 8b 45 e8 01 45 f0 8b 45 d0 90 01 45 f0 8b 45 f0 89 45 ec 8b 4d f4 8b c7 d3 e8 03 45 cc 89 45 f8 8b 45 ec 31 45 fc } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_StopCrypt_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/StopCrypt.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 0c 8b 44 24 24 03 44 24 10 c7 05 90 01 04 00 00 00 00 33 c6 33 c1 2b f8 89 44 24 10 8b c7 c1 e0 04 90 00 } //01 00 
		$a_01_1 = {8b 44 24 28 01 44 24 0c 8b c7 c1 e8 05 8d 34 3b } //01 00 
		$a_01_2 = {31 74 24 0c 8b 44 24 10 31 44 24 0c 8b 44 24 0c 29 44 24 14 } //00 00 
	condition:
		any of ($a_*)
 
}