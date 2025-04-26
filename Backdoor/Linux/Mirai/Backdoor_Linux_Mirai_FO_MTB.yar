
rule Backdoor_Linux_Mirai_FO_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.FO!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3c 30 97 e5 07 00 53 e3 3c 50 94 c5 1f ?? ?? ?? 04 00 a0 e1 cd ?? ?? ?? 00 20 a0 e3 00 00 5a e3 00 20 c6 e5 b2 ?? ?? ?? 44 30 d7 e5 02 00 53 e1 b1 ?? ?? ?? 05 30 dd e5 2d 00 53 e3 02 10 a0 01 02 ?? ?? ?? 05 00 5b e3 00 10 a0 c3 } //1
		$a_01_1 = {00 00 59 e3 00 00 89 15 00 00 5a e3 02 71 e0 03 02 71 a0 13 00 60 e0 03 00 60 a0 13 00 30 5b e2 01 30 a0 13 07 00 55 e1 00 20 a0 e3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}