
rule Backdoor_Linux_Mirai_JS_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.JS!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {10 40 2d e9 25 00 ?? ef 01 0a 70 e3 00 40 a0 e1 03 ?? ?? ?? e0 00 00 eb 00 30 64 e2 00 30 80 e5 00 40 e0 e3 04 00 a0 e1 10 80 bd e8 } //1
		$a_01_1 = {80 30 80 e2 06 0d 53 e3 80 10 a0 e1 0e f0 a0 21 18 30 9f e5 00 30 93 e5 03 20 81 e0 03 10 d1 e7 01 30 d2 e5 03 3c a0 e1 43 08 81 e1 0e f0 a0 e1 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}