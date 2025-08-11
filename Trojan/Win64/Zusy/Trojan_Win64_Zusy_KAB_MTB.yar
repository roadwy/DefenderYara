
rule Trojan_Win64_Zusy_KAB_MTB{
	meta:
		description = "Trojan:Win64/Zusy.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c1 41 33 c0 69 c8 93 01 00 01 8b c1 c1 e8 0d 33 c1 69 c8 95 e9 d1 5b 44 8b c1 41 c1 e8 0f 44 33 c1 45 84 c9 75 } //10
		$a_01_1 = {b8 4f ec c4 4e 41 f7 e8 c1 fa 04 8b c2 c1 e8 1f 03 d0 0f b7 c2 6b c8 34 41 0f b7 c0 66 2b c1 66 83 c0 38 66 41 31 01 41 ff c0 4d 8d 49 02 41 81 f8 } //8
		$a_01_2 = {66 2b c1 66 83 c0 38 66 41 31 01 41 ff c0 4d 8d 49 02 41 81 f8 } //7
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*8+(#a_01_2  & 1)*7) >=25
 
}