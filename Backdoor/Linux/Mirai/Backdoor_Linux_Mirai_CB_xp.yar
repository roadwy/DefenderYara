
rule Backdoor_Linux_Mirai_CB_xp{
	meta:
		description = "Backdoor:Linux/Mirai.CB!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {30 a0 e3 4d 51 ce e5 97 05 16 e5 50 c1 8e e5 93 35 46 e5 20 c0 9d e5 4c 31 ce e5 24 30 9d e5 51 1c 8d } //1
		$a_00_1 = {19 30 96 e5 00 00 53 e3 04 30 a0 13 93 35 46 15 93 35 46 05 55 ff ff 0a 00 30 e0 e3 00 50 a0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}