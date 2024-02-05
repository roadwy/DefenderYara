
rule Trojan_Win32_Hancitor_GY_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0f b7 e9 8b d3 2b d7 03 15 90 02 04 8b c5 2b c3 83 e8 90 01 01 8b fa 8b 16 3b 05 90 02 04 90 18 2b c1 03 05 90 02 04 81 c2 90 02 04 0f b7 c8 0f b7 c1 2b c7 89 16 83 c0 90 01 01 83 c6 90 01 01 83 6c 24 90 01 01 01 89 15 90 02 04 a3 90 02 04 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}