
rule Backdoor_Linux_Gafgyt_BS_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.BS!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {a0 00 0b e5 a4 10 0b e5 a8 20 0b e5 ac 30 0b e5 00 30 a0 e3 9c 30 0b e5 a4 30 1b e5 98 30 0b e5 94 30 4b e2 10 30 0b e5 00 30 a0 e3 14 30 0b e5 06 00 00 } //1
		$a_00_1 = {30 9f e5 00 10 93 e5 20 20 1b e5 24 30 1b e5 02 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}