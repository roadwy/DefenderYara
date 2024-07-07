
rule Trojan_Win32_Azorult_AA_MTB{
	meta:
		description = "Trojan:Win32/Azorult.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {66 85 c0 46 3d 90 01 04 ff 37 3d 90 01 04 59 81 ff 90 01 04 e8 90 01 02 00 00 85 ff 39 c1 75 90 00 } //1
		$a_02_1 = {51 66 81 fa 90 01 02 31 34 24 66 81 fa 90 01 02 59 66 85 db c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Azorult_AA_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 f6 85 ff 90 01 02 81 ff 90 01 02 00 00 75 0a 6a 00 6a 00 ff 15 90 01 04 8b 15 90 01 04 69 d2 90 01 04 89 15 90 01 04 81 05 90 01 08 a0 90 01 04 30 04 1e 46 3b f7 7c c5 90 00 } //1
		$a_02_1 = {51 6a 00 ff 15 90 01 04 8a 94 3e 90 01 04 a1 90 01 04 88 14 30 5f 8b 4d fc 33 cd e8 90 01 04 8b e5 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}