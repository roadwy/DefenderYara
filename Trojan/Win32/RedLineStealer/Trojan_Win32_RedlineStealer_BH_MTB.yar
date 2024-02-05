
rule Trojan_Win32_RedlineStealer_BH_MTB{
	meta:
		description = "Trojan:Win32/RedlineStealer.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 89 44 24 14 8b 44 24 44 01 44 24 14 8b 44 24 10 33 44 24 1c 89 7c 24 30 89 44 24 10 89 44 24 4c 8b 44 24 4c 89 44 24 30 8b 44 24 14 31 44 24 30 8b 4c 24 30 89 4c 24 10 89 3d 90 02 04 8b 44 24 10 29 44 24 18 81 44 24 2c 47 86 c8 61 4b 0f 85 90 00 } //01 00 
		$a_03_1 = {89 44 24 14 8b 4c 24 10 33 4c 24 1c 8b 44 24 14 03 c5 33 c1 83 3d 90 02 04 0c c7 05 90 02 04 ee 3d ea f4 89 4c 24 10 89 44 24 14 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}