
rule Trojan_Win32_Dridex_DEM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {2b c8 66 03 d1 8b 4c 24 90 01 01 0f b7 c2 66 89 15 90 01 04 99 2b c8 0f b7 c6 1b fa 83 c1 90 01 01 99 83 d7 90 01 01 3b c8 90 13 a1 90 02 0f 03 c3 03 c5 66 a3 90 01 04 8b 44 24 90 01 01 05 90 01 04 a3 90 01 04 89 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}