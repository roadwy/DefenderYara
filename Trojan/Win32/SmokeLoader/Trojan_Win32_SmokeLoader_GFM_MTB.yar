
rule Trojan_Win32_SmokeLoader_GFM_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c7 89 7d 90 01 01 e8 90 01 04 8b 45 90 01 01 01 45 90 01 01 33 d2 89 55 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 02 01 45 90 01 01 8b 45 90 01 01 89 45 90 01 01 8b 4d 90 01 01 8b c7 d3 e8 03 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 81 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}