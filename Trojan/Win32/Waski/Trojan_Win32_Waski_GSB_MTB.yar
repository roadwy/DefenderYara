
rule Trojan_Win32_Waski_GSB_MTB{
	meta:
		description = "Trojan:Win32/Waski.GSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {89 4d fc ba ec 8c 8b e8 89 55 b8 b8 90 01 04 89 45 ac b9 90 01 04 8b d1 c1 ca 06 89 55 c0 8b c1 35 90 01 04 89 45 d4 c1 c9 1a 89 4d dc 89 2d 90 00 } //05 00 
		$a_02_1 = {8b 13 8b 45 d8 2d 90 01 04 03 d8 4e 89 17 b8 90 01 04 35 90 01 04 03 f8 85 f6 75 be 90 00 } //05 00 
		$a_02_2 = {33 c2 33 ff 3b d7 0f 84 90 01 04 8b d7 e9 19 03 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}