
rule Backdoor_Linux_Gafgyt_BR_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.BR!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {02 3c b9 79 42 34 26 20 62 00 18 80 82 8f 80 18 } //1
		$a_00_1 = {58 30 42 8c 18 80 83 8f 80 20 02 00 e8 38 62 24 21 10 82 00 00 00 44 8c 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}