
rule Trojan_Win32_StealC_CHC_MTB{
	meta:
		description = "Trojan:Win32/StealC.CHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d6 d3 ea 8d 04 33 89 45 ec c7 05 90 01 04 ee 3d ea f4 03 55 90 01 01 8b 45 ec 31 45 fc 33 55 fc 81 3d 90 01 04 13 02 00 00 89 55 ec 75 90 00 } //01 00 
		$a_03_1 = {c1 e0 04 89 45 fc 8b 45 e0 01 45 fc 8b 45 f4 8b 4d f8 8b f0 d3 ee 8d 14 03 31 55 fc 03 75 90 01 01 81 3d 90 01 04 21 01 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}