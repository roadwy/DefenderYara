
rule Trojan_Win32_RedLineStealer_AA_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {33 ca 89 4c 24 90 01 01 89 5c 24 90 01 01 8b 44 24 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 54 24 90 01 01 89 54 24 90 01 01 89 1d 90 01 04 8b 44 24 90 01 01 29 44 24 90 01 01 81 44 24 90 01 05 ff 4c 24 90 01 01 0f 85 90 01 04 8b 44 24 90 01 01 8b 4c 24 90 01 01 89 08 89 78 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_RedLineStealer_AA_MTB_2{
	meta:
		description = "Trojan:Win32/RedLineStealer.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c7 33 45 90 01 01 33 c1 81 3d 90 01 08 89 45 90 01 01 75 90 0a 40 00 81 ad 90 01 08 81 ad 90 01 08 b8 90 01 04 8b 85 90 00 } //01 00 
		$a_03_1 = {2b d8 89 75 90 01 01 81 6d 90 01 05 81 45 90 01 05 8b 4d 90 01 01 8b f3 d3 e6 8b 4d 90 01 01 8b c3 d3 e8 03 b5 90 01 04 89 45 90 01 01 8b 85 90 01 04 01 45 90 01 01 8b 85 90 01 04 03 c3 33 f0 81 3d 90 01 08 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}