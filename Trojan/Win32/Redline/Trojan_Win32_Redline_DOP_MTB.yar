
rule Trojan_Win32_Redline_DOP_MTB{
	meta:
		description = "Trojan:Win32/Redline.DOP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c7 d3 e8 8b 4c 24 90 01 01 c7 05 90 01 08 89 44 24 90 01 01 8d 44 24 90 01 01 e8 90 01 04 8b 44 24 90 01 01 31 44 24 90 01 01 81 3d 90 01 08 75 90 00 } //01 00 
		$a_03_1 = {8b c6 c1 e8 90 01 01 03 c5 33 44 24 90 01 01 33 c8 2b f9 8d 44 24 90 01 01 89 4c 24 90 01 01 89 7c 24 90 01 01 e8 90 01 04 83 6c 24 90 01 02 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}