
rule Backdoor_Linux_Mirai_JO_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.JO!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0d c0 a0 e1 00 d8 2d e9 04 b0 4c e2 14 d0 4d e2 1c 00 0b e5 00 30 a0 e3 18 30 0b e5 1c 30 1b e5 ff 30 03 e2 03 00 a0 e1 } //1
		$a_03_1 = {00 30 d0 e5 00 30 53 e2 01 30 a0 13 04 00 58 e3 00 30 a0 c3 00 00 53 e3 db ?? ?? ?? 80 60 9d e5 68 11 9f e5 06 00 a0 e1 5e ?? ?? ?? 00 00 50 e3 01 50 a0 03 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}