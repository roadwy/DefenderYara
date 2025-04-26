
rule Trojan_Win32_Fragtor_AFG_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.AFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 06 03 05 88 65 41 00 6a 00 6a 04 68 88 65 41 00 50 57 ff d3 83 c6 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Fragtor_AFG_MTB_2{
	meta:
		description = "Trojan:Win32/Fragtor.AFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b ca c1 f9 06 83 e2 3f 6b d2 38 8b 0c 8d 48 8f 50 00 88 44 11 29 8b 0b 8b c1 c1 f8 06 83 e1 3f 6b d1 38 8b 0c 85 48 8f 50 00 8b 45 14 c1 e8 10 32 44 11 2d 24 01 30 44 11 2d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Fragtor_AFG_MTB_3{
	meta:
		description = "Trojan:Win32/Fragtor.AFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 05 70 48 01 10 a2 10 53 01 10 0f b6 05 71 48 01 10 a2 11 53 01 10 0f b6 05 72 48 01 10 a2 12 53 01 10 0f b6 05 73 48 01 10 a2 13 53 01 10 0f b6 05 74 48 01 10 a2 14 53 01 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Fragtor_AFG_MTB_4{
	meta:
		description = "Trojan:Win32/Fragtor.AFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {c8 6a 40 9c 1c 8d c1 c3 fe c1 86 08 0e 53 50 c7 86 b0 6c 0e a6 1a 05 cb a5 dd b4 12 0a b8 c0 4b e5 6b 4f 30 88 16 22 66 18 c4 31 d8 d3 b9 7c df a0 17 a4 0b a8 ac ad d9 cc 96 } //3
		$a_01_1 = {2a 2c 7f 3a 51 a0 0c b6 81 28 09 be 9f cb b7 81 2c 0b 30 34 88 81 38 17 40 cb e5 72 f9 0b 44 48 4c 50 38 80 00 9f 54 8b c1 bc a0 f1 7e c1 df b1 da c2 6a 08 59 8b fe f3 ab } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}