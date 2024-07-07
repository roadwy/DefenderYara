
rule Backdoor_Linux_Gafgyt_CN_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.CN!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {34 42 79 b9 00 62 20 26 8f 82 80 18 00 06 18 80 24 42 5a 88 00 62 10 21 ac 44 00 00 8f c2 00 08 } //1
		$a_00_1 = {00 24 42 5a 88 ac 43 00 04 8f c3 00 18 3c 02 3c 6e 34 42 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}