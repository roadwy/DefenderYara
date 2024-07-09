
rule Backdoor_Linux_Mirai_ER_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.ER!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {21 00 00 3f 92 10 00 1b 96 14 23 ff d0 2f be cf 94 10 20 03 } //1
		$a_03_1 = {05 00 00 3f a3 30 60 10 ac 10 a3 ff 82 10 20 00 a5 37 60 10 83 28 60 02 d4 07 be b8 a7 3d e0 18 e0 02 80 01 80 a4 80 16 02 80 ?? ?? b6 04 20 14 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}