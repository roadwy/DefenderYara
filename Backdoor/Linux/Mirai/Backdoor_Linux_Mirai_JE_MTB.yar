
rule Backdoor_Linux_Mirai_JE_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.JE!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {30 40 2d e9 0c 40 8d e2 30 00 94 e8 24 01 ?? ef 01 0a 70 e3 00 40 a0 e1 03 ?? ?? ?? f9 f9 ff eb 00 30 64 e2 00 30 80 e5 00 40 e0 e3 } //1
		$a_03_1 = {00 20 64 22 02 40 03 20 c8 00 9f e5 0f e0 a0 e1 05 f0 a0 e1 04 00 a0 e1 06 05 00 eb 01 00 70 e3 00 50 a0 01 04 ?? ?? ?? 03 30 80 e2 03 50 c3 e3 05 00 50 e1 05 00 60 10 fe 04 00 1b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}