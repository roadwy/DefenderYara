
rule Backdoor_Linux_Mirai_HN_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.HN!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 00 50 e3 04 c0 94 e5 0a 00 00 1a 73 2e 8d e2 ac 32 a0 e1 08 20 82 e2 03 11 82 e0 38 31 11 e5 1f 20 0c e2 10 32 83 e1 06 00 5c e1 0c 60 a0 c1 38 31 01 e5 } //1
		$a_03_1 = {b4 37 9f e5 00 20 93 e5 12 3e a0 e3 90 01 01 23 24 e0 0c 00 94 e5 01 00 50 e3 1e 10 a0 83 02 90 01 03 00 00 50 e3 33 90 01 03 05 10 a0 e3 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}