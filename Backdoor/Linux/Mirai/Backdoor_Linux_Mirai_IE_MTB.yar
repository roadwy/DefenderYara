
rule Backdoor_Linux_Mirai_IE_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.IE!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {c2 04 40 13 85 30 60 05 85 28 a0 02 84 00 80 19 c4 00 bf 58 85 38 80 01 80 88 a0 01 22 80 00 06 a4 04 a0 01 84 04 c0 11 82 10 20 01 c2 28 a0 04 a4 04 a0 01 a2 04 62 9c 80 a4 80 15 26 bf ff ca d0 04 40 13 } //1
		$a_00_1 = {9a 06 00 11 c4 06 00 00 c4 20 ff f8 c2 0e 20 04 c2 28 ff fc 82 04 80 04 b2 06 7f fb c4 20 60 04 b0 06 20 05 82 10 20 02 c2 31 00 12 88 01 20 18 86 00 e0 18 80 a6 00 0d 12 bf ff f3 ba 10 00 08 80 a6 60 00 02 80 00 33 aa 10 20 00 c2 4b 00 11 80 a0 60 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}