
rule Trojan_Win32_Emotet_R{
	meta:
		description = "Trojan:Win32/Emotet.R,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 05 00 00 "
		
	strings :
		$a_00_0 = {83 e4 f8 83 ec 78 31 c0 66 c7 44 24 72 78 dd c7 44 24 5c 95 13 b3 5d } //10
		$a_00_1 = {66 83 c7 20 66 83 c6 bf 66 83 fe 1a 66 0f 42 df 66 39 da 0f 94 c0 24 01 } //10
		$a_03_2 = {bb a3 0c 23 c7 84 [0-05] e4 ac d0 19 c7 84 [0-05] b1 e1 01 5d 8b 8c [0-05] c7 84 [0-05] 0a b0 51 23 } //10
		$a_03_3 = {c0 28 80 41 [0-04] 3d 27 74 00 2e } //10
		$a_03_4 = {66 c7 44 24 ?? 78 dd c7 44 24 ?? 95 13 b3 5d } //10
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_03_2  & 1)*10+(#a_03_3  & 1)*10+(#a_03_4  & 1)*10) >=20
 
}