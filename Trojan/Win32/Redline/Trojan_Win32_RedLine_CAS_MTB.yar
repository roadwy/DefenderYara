
rule Trojan_Win32_RedLine_CAS_MTB{
	meta:
		description = "Trojan:Win32/RedLine.CAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b 45 dc 99 b9 41 00 00 00 f7 f9 8b 45 08 0f be 04 10 6b c0 90 01 01 99 b9 90 01 01 00 00 00 f7 f9 8b 55 0c 03 55 dc 0f b6 0a 33 c8 8b 55 0c 03 55 dc 88 0a eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_RedLine_CAS_MTB_2{
	meta:
		description = "Trojan:Win32/RedLine.CAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b 44 24 14 89 44 24 20 8b 44 24 28 01 44 24 20 8b 4c 24 1c 8b 54 24 14 d3 ea 8b 4c 24 3c 8d 44 24 2c c7 05 90 02 04 ee 3d ea f4 89 54 24 2c e8 90 02 04 8b 44 24 20 31 44 24 10 81 3d 90 02 04 e6 09 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}