
rule Backdoor_Linux_Mirai_JN_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.JN!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2a 01 00 eb 00 30 64 e2 00 30 80 e5 00 40 e0 e3 04 00 a0 e1 04 d0 8d e2 10 40 bd e8 0c d0 8d e2 0e f0 a0 e1 01 20 a0 e1 00 10 9f e5 e5 ff ff ea } //1
		$a_03_1 = {10 40 2d e9 08 40 9d e5 ac 00 ?? ef 01 0a 70 e3 00 40 a0 e1 03 ?? ?? ?? 17 01 00 eb 00 30 64 e2 00 30 80 e5 00 40 e0 e3 04 00 a0 e1 10 80 bd e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}