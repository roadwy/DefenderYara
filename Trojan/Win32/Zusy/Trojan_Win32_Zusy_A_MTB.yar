
rule Trojan_Win32_Zusy_A_MTB{
	meta:
		description = "Trojan:Win32/Zusy.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 83 e0 03 8a 80 90 01 04 30 86 90 01 04 46 81 fe 7e 07 00 00 72 e4 33 f6 ff d7 8b c6 83 e0 03 8a 80 90 01 04 30 86 90 01 04 46 81 fe 00 76 00 00 72 e4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zusy_A_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4d f8 81 c1 5b 05 00 00 89 4d f8 8b 55 f8 81 ea 4d 07 00 00 89 55 f8 8b 45 e8 2d 06 09 00 00 89 45 e8 8b 4d fc 81 e9 06 02 00 00 89 4d fc 8b 55 ec 81 c2 6e 1f 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}