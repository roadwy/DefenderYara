
rule Backdoor_Linux_Gafgyt_BO_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.BO!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {00 01 44 30 00 01 45 ac 00 01 48 b8 9d e3 bf 90 f0 27 a0 44 03 00 00 d1 84 10 } //1
		$a_00_1 = {bc 10 00 00 9c 23 a0 18 d2 03 a0 58 94 03 a0 5c 11 00 00 5b } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}