
rule Backdoor_Linux_Mirai_JT_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.JT!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 20 a0 e1 c2 3f a0 e1 23 1c a0 e1 01 30 82 e0 ff 30 03 e2 03 30 61 e0 ff 10 03 e2 38 20 1b e5 5c 31 1b e5 94 03 03 e0 02 30 83 e0 05 20 83 e0 01 30 a0 e1 00 30 c2 e5 30 30 1b e5 01 30 83 e2 30 30 0b e5 } //1
		$a_01_1 = {00 10 a0 e1 50 31 1b e5 0c 20 93 e5 50 31 1b e5 08 30 93 e5 02 30 63 e0 01 30 83 e2 01 00 a0 e1 03 10 a0 e1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}