
rule Trojan_Win64_Fareit_MK_MTB{
	meta:
		description = "Trojan:Win64/Fareit.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 c3 42 0f b6 04 01 01 d8 44 31 c8 49 ff c8 41 89 d9 49 83 f8 07 } //15
		$a_01_1 = {89 d8 42 0f b6 5c 01 08 01 c3 44 31 d3 49 ff c0 41 89 c2 49 83 f8 10 } //15
		$a_01_2 = {89 c1 c1 e9 18 88 0a 89 c1 c1 e9 10 88 4a 01 88 62 02 88 42 03 89 d8 c1 e8 18 88 42 04 89 d8 c1 e8 10 88 42 05 88 7a 06 88 5a 07 } //20
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*15+(#a_01_2  & 1)*20) >=50
 
}