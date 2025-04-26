
rule Backdoor_Linux_Mirai_CR_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.CR!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_00_0 = {00 b0 a0 e3 00 e0 a0 e3 04 10 9d e4 0d 20 a0 e1 04 20 2d e5 04 00 2d e5 10 c0 9f e5 04 c0 2d e5 0c 00 9f e5 0c 30 9f e5 ac 2f 00 } //1
		$a_00_1 = {a0 e1 15 20 a0 e3 04 00 a0 e1 a0 3d 9f e5 45 07 00 eb 05 10 a0 e1 00 80 a0 e1 17 20 a0 e3 04 00 a0 e1 01 30 a0 e3 71 07 00 eb 05 10 a0 e1 07 20 a0 e3 50 30 a0 e3 00 60 a0 e1 04 } //1
		$a_00_2 = {00 80 e3 00 00 c4 e5 00 00 d4 e5 18 c0 9d e5 b0 00 c0 e3 00 50 a0 e3 40 00 80 e3 14 c0 8c e2 00 00 c4 e5 b2 c0 c4 e1 01 50 c4 e5 03 70 a0 e1 01 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=1
 
}