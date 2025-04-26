
rule Backdoor_Linux_Mirai_KK_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.KK!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {fd 7b be a9 fd 03 00 91 f3 53 01 a9 34 1c 00 72 e1 01 00 54 f3 53 41 a9 01 00 80 52 fd 7b c2 a8 da 01 00 14 } //1
		$a_01_1 = {e1 03 14 2a e0 03 02 aa d5 01 00 94 60 ff ff b5 e0 03 13 aa f3 53 41 a9 fd 7b c2 a8 c0 03 5f d6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}