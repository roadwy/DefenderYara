
rule Trojan_Win32_Redline_GNV_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b6 0e 83 c4 90 01 01 0f b6 07 8b 74 24 90 01 01 03 c8 0f b6 c1 8a 84 04 90 01 04 30 85 90 01 04 45 81 fd 90 01 04 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_GNV_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {0f be 4d 02 c1 e1 10 0f be 45 01 c1 e0 08 33 c8 0f be 45 00 33 c1 } //0a 00 
		$a_01_1 = {8b 44 24 24 8b 54 24 18 40 89 44 24 24 3b 44 24 3c } //00 00 
	condition:
		any of ($a_*)
 
}