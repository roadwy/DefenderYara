
rule Trojan_Win32_SmokeLoader_RG_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 dc 01 45 fc 8b 4d f8 8b 45 f4 8b fb d3 ef 03 c3 31 45 fc 03 7d d4 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_SmokeLoader_RG_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b f7 d3 ee 8d 04 3b 89 45 e0 c7 05 90 01 04 ee 3d ea f4 03 75 e4 8b 45 e0 31 45 fc 33 75 fc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}