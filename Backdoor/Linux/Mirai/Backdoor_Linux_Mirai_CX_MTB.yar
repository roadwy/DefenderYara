
rule Backdoor_Linux_Mirai_CX_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.CX!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {0c 31 93 e7 1f 20 00 e2 01 60 a0 e3 16 32 83 e1 0e 00 50 e1 0e 00 a0 b1 0c 31 81 e7 01 ea 8d e2 0a c0 a0 e3 e4 c1 8e e5 47 cd 8d e2 00 50 a0 e3 24 c0 8c e2 42 1d 8d e2 01 2a 8d e2 00 c0 8d e5 06 00 80 e0 04 10 81 e2 04 20 82 e2 05 30 a0 e1 e8 51 8e e5 e0 02 00 eb 05 00 58 e1 00 40 a0 e1 05 20 a0 c1 08 00 a0 c1 ec 13 9f c5 7e 02 00 cb 01 00 74 e3 94 00 00 0a } //1
		$a_00_1 = {30 d2 e7 65 30 23 e2 00 30 c2 e7 01 20 82 e2 01 00 52 e1 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}