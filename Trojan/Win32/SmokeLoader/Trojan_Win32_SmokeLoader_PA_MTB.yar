
rule Trojan_Win32_SmokeLoader_PA_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c3 c1 e8 90 01 01 c7 05 90 01 08 89 45 08 8b 45 90 01 01 01 45 90 01 01 8b c3 c1 e0 04 03 c6 33 45 08 33 45 0c 50 8d 45 f4 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_SmokeLoader_PA_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 55 fc 83 c2 01 89 55 fc 81 7d fc 40 14 00 00 73 29 8b 45 fc 0f be 88 90 01 03 00 8b 45 fc 33 d2 be 20 00 00 00 f7 f6 0f be 92 90 01 03 00 33 ca 8b 45 f8 03 45 fc 88 08 eb c5 90 00 } //01 00 
		$a_02_1 = {6a 40 68 00 30 00 00 68 40 14 00 00 6a 00 ff 15 90 01 03 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}