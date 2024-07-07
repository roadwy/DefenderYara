
rule Backdoor_Linux_Mirai_CU_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.CU!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {a0 e1 b5 dd 4d e2 04 d0 4d e2 08 20 a0 e3 00 30 a0 e3 00 a0 a0 e1 01 b0 a0 e1 04 00 a0 e1 05 10 a0 e1 07 0b 00 eb 05 10 a0 e1 00 70 a0 e1 18 20 a0 e3 04 00 a0 e1 01 30 a0 e3 f9 0b 00 } //1
		$a_00_1 = {00 90 e5 0c 10 84 e2 80 20 a0 e3 47 25 00 eb 04 30 94 e5 e0 ff ff ea 10 40 2d e9 00 40 a0 e1 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}