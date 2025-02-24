
rule Backdoor_Linux_Mirai_KJ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.KJ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 20 9f e5 80 40 2d e9 02 20 8f e0 00 30 a0 e1 2d 70 a0 e3 00 00 00 ef 03 00 50 e1 2c 30 9f e5 03 00 82 e7 00 00 a0 23 05 00 00 2a 20 30 9f e5 2c d5 ff eb 03 30 9f e7 0c 20 a0 e3 03 20 80 e7 00 00 e0 e3 } //1
		$a_01_1 = {14 20 90 e5 30 40 2d e9 40 20 81 e5 0c 30 90 e5 00 00 53 e3 04 d0 4d e2 00 40 a0 e1 01 50 a0 e1 0e 00 00 1a 02 00 a0 e3 04 10 a0 e1 05 20 a0 e1 10 c0 94 e5 0f e0 a0 e1 1c ff 2f e1 07 00 50 e3 04 00 00 0a 08 00 50 e3 86 ec ff 1b 04 00 a0 e1 05 10 a0 e1 d1 ff ff eb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}