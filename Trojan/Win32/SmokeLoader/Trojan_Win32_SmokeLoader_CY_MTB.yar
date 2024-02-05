
rule Trojan_Win32_SmokeLoader_CY_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b 44 24 24 89 44 24 20 8b 44 24 28 01 44 24 20 8b 4c 24 18 8b c6 d3 e8 8b 4c 24 30 c7 05 90 02 04 ee 3d ea f4 89 44 24 24 8d 44 24 24 e8 90 02 04 8b 44 24 20 31 44 24 10 81 3d 90 02 04 e6 09 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}