
rule Trojan_Win32_Redline_GNV_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b6 0e 83 c4 90 01 01 0f b6 07 8b 74 24 90 01 01 03 c8 0f b6 c1 8a 84 04 90 01 04 30 85 90 01 04 45 81 fd 90 01 04 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}