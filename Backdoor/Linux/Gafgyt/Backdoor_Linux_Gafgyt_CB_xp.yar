
rule Backdoor_Linux_Gafgyt_CB_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.CB!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {03 1a 03 3c 36 7c 53 35 31 1a 01 12 2e 0a 02 21 1e e2 67 e1 58 72 2e 81 1e e1 58 8c 36 } //1
		$a_00_1 = {c8 71 1e 51 12 22 e3 61 c8 71 1e 52 23 d1 1c 32 21 d1 21 11 e3 61 c8 71 1e 52 21 d1 1c 32 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}