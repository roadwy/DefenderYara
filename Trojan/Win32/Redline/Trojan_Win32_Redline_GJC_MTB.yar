
rule Trojan_Win32_Redline_GJC_MTB{
	meta:
		description = "Trojan:Win32/Redline.GJC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b6 84 1d 90 01 04 88 84 3d 90 01 04 88 8c 1d 90 01 04 0f b6 84 3d 90 01 04 03 c2 0f b6 c0 0f b6 84 05 90 01 04 32 86 90 01 04 88 86 90 01 04 c7 45 90 01 05 46 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}