
rule Trojan_Win32_Redline_ASAF_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e1 04 03 cd 33 d1 8b 4c 24 14 03 c8 33 d1 2b fa 8b d7 c1 e2 04 c7 05 90 02 04 00 00 00 00 89 54 24 10 8b 44 24 20 01 44 24 10 8b 5c 24 14 03 df 81 3d 90 02 04 be 01 00 00 75 90 00 } //01 00 
		$a_01_1 = {33 f3 31 74 24 10 8b 44 24 10 29 44 24 18 8b 44 24 24 29 44 24 14 ff 4c 24 1c 0f } //00 00 
	condition:
		any of ($a_*)
 
}