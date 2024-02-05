
rule Trojan_Win32_Redline_BHG_MTB{
	meta:
		description = "Trojan:Win32/Redline.BHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d0 c1 ea 05 03 54 24 20 03 c6 33 d1 33 d0 2b fa 8b cf c1 e1 04 81 3d 90 01 04 8c 07 00 00 c7 05 90 01 04 00 00 00 00 89 4c 24 0c 75 90 00 } //01 00 
		$a_03_1 = {33 f3 31 74 24 0c 8b 44 24 0c 29 44 24 10 81 3d 90 01 04 93 00 00 00 75 10 68 58 40 40 00 8d 4c 24 74 51 ff 15 90 01 04 8d 44 24 14 e8 90 01 04 ff 4c 24 18 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}