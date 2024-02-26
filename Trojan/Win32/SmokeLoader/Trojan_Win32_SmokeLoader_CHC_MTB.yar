
rule Trojan_Win32_SmokeLoader_CHC_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 c1 e0 04 89 45 fc 8b 45 dc 01 45 fc 8b 45 f8 8b 4d f4 8b f0 d3 ee 8d 14 07 31 55 fc 03 75 d4 81 3d 90 01 04 21 01 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}