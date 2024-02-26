
rule Trojan_Win32_StealC_RAY_MTB{
	meta:
		description = "Trojan:Win32/StealC.RAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 89 45 fc 8b 45 e0 01 45 fc 8b 45 f4 8b 4d f8 8d 14 03 31 55 fc d3 e8 03 45 e4 81 3d 90 01 04 21 01 00 00 8b f8 75 90 00 } //01 00 
		$a_03_1 = {56 ff 15 14 90 01 03 31 7d fc 8b 45 fc 29 45 f0 81 c3 90 01 04 ff 4d e8 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}