
rule Trojan_Win32_Predator_PA_MTB{
	meta:
		description = "Trojan:Win32/Predator.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 75 ec 25 1b 07 d0 4d 81 6d ec 88 eb 73 22 bb 87 d5 7c 3a 81 45 ec 8c eb 73 22 8b 45 f8 8b 4d ec 8b d0 d3 e2 8b c8 c1 e9 05 03 4d 90 01 01 03 55 90 01 01 89 35 90 01 04 33 d1 8b 4d f4 03 c8 33 d1 29 55 f0 81 3d 90 01 04 90 01 02 00 00 75 90 00 } //01 00 
		$a_02_1 = {89 55 ec 25 1b 07 d0 4d 81 6d ec 88 eb 73 22 bb 87 d5 7c 3a 81 45 ec 8c eb 73 22 8b 4d ec 8b c7 d3 e0 8b cf c1 e9 05 03 4d 90 01 01 03 45 90 01 01 89 15 90 01 04 33 c1 8b 4d f4 03 cf 33 c1 29 45 f0 a1 90 01 04 3d 90 01 02 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}