
rule Backdoor_Linux_Mirai_BK_xp{
	meta:
		description = "Backdoor:Linux/Mirai.BK!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {30 43 e2 19 00 53 e3 0c 20 c9 97 05 3a 8d 92 6c } //1
		$a_00_1 = {30 a0 e3 a8 35 46 e5 ac 05 16 e5 e6 2a 00 eb 00 30 e0 e3 ac 35 06 e5 40 20 } //1
		$a_00_2 = {3c 8d e2 70 30 83 e2 03 20 8c e0 a4 30 12 e5 33 31 a0 e1 01 00 13 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}