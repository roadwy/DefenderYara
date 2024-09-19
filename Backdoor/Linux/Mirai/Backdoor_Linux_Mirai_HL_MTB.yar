
rule Backdoor_Linux_Mirai_HL_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.HL!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {10 40 2d e9 ff 00 00 e2 03 40 a0 e1 ff 20 02 e2 00 c0 a0 e3 04 00 00 ea 04 30 d1 e5 02 00 53 e1 08 10 81 e2 00 40 9e 05 03 00 00 0a 00 00 5c e1 01 e0 a0 e1 01 c0 8c e2 f6 ff ff ba 04 00 a0 e1 10 80 bd e8 } //1
		$a_00_1 = {00 c0 a0 e3 04 00 00 ea 00 30 d0 e5 01 20 d0 e5 02 34 83 e1 03 c0 8c e0 02 00 80 e2 01 00 51 e3 02 10 41 e2 f7 ff ff 8a 00 30 d0 05 03 c0 8c 00 0c 08 a0 e1 20 08 a0 e1 2c 08 80 e0 20 08 80 e0 00 00 e0 e1 00 08 a0 e1 20 08 a0 e1 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}