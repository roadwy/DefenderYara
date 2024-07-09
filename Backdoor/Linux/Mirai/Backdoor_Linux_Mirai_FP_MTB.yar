
rule Backdoor_Linux_Mirai_FP_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.FP!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 10 95 e5 34 30 91 e5 00 00 53 e3 08 ?? ?? ?? 10 20 91 e5 18 30 91 e5 03 00 52 e1 01 00 d2 34 10 20 81 35 04 ?? ?? ?? 01 00 a0 e1 9a 04 00 eb } //1
		$a_03_1 = {f0 45 2d e9 8d 70 a0 e3 04 d0 4d e2 00 00 00 ef 01 0a 70 e3 00 50 a0 e1 06 ?? ?? ?? 78 30 9f e5 00 20 60 e2 03 30 9f e7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}