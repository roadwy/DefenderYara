
rule Backdoor_Linux_Gafgyt_BY_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.BY!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {30 c2 e5 10 30 1b e5 00 30 93 e5 01 20 83 e2 10 30 1b e5 00 20 83 e5 04 00 00 } //1
		$a_00_1 = {30 1b e5 00 00 53 e3 0a 00 00 0a 28 30 1b e5 0a 00 53 e3 07 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}