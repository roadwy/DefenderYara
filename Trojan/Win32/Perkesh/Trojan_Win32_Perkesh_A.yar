
rule Trojan_Win32_Perkesh_A{
	meta:
		description = "Trojan:Win32/Perkesh.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 10 6a 03 ff 15 90 01 02 00 10 a3 90 01 02 00 10 6a 64 ff 15 90 01 02 00 10 eb f6 90 00 } //02 00 
		$a_03_1 = {8b 46 04 3d 01 02 00 00 74 14 3d 02 02 00 00 74 0d 3d 02 01 00 00 75 90 01 01 83 7e 08 0d 90 00 } //01 00 
		$a_01_2 = {bd f0 c9 bd b6 be b0 d4 00 } //01 00 
		$a_01_3 = {33 36 30 b0 b2 c8 ab ce c0 ca bf 00 c8 f0 d0 c7 00 } //01 00 
		$a_01_4 = {c8 f0 d0 c7 00 } //01 00 
		$a_01_5 = {bf a8 b0 cd cb b9 bb f9 00 } //00 00 
	condition:
		any of ($a_*)
 
}