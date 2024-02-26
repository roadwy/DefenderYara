
rule Trojan_Win32_StealC_NIT_MTB{
	meta:
		description = "Trojan:Win32/StealC.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 eb 89 45 ec c7 05 90 01 04 ee 3d ea f4 03 5d d4 8b cb 8b 45 ec 31 45 fc 33 4d fc 81 3d 90 01 04 13 02 00 00 89 4d ec 75 90 00 } //01 00 
		$a_03_1 = {8b 45 f8 c1 e0 04 89 45 fc 8b 45 d8 01 45 fc 8b 4d f8 8d 04 0f 31 45 fc 8b f9 8b 4d f4 d3 ef 03 7d d0 81 3d 90 01 04 21 01 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}