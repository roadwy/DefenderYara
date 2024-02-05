
rule Trojan_Win32_Dridex_DG_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {6b c0 62 2b c1 8b 3d 90 01 04 8b d7 6b d2 4d 8d 54 10 62 a1 90 01 04 03 c1 3d 65 03 90 00 } //0a 00 
		$a_03_1 = {2b c1 05 59 a0 00 00 a3 90 01 04 81 c2 00 cf 7e 01 89 15 90 01 04 89 94 37 90 01 04 a1 90 01 04 8b 1d 90 01 04 8b c8 6b c9 1b 03 cb 83 c6 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}