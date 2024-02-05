
rule Trojan_Win64_BumbleBee_AA{
	meta:
		description = "Trojan:Win64/BumbleBee.AA,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //0a 00 
		$a_03_1 = {b8 01 00 00 00 87 05 90 01 04 83 f8 01 74 f0 48 83 3d 90 01 04 00 90 00 } //0a 00 
		$a_01_2 = {33 c9 ba 58 02 00 00 41 b8 00 30 00 00 44 8d 49 04 ff 15 } //00 00 
		$a_00_3 = {5d 04 00 00 77 1f 05 80 5c 33 00 00 78 1f 05 80 00 00 01 00 } //08 00 
	condition:
		any of ($a_*)
 
}