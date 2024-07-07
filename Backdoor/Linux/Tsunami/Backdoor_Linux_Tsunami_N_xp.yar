
rule Backdoor_Linux_Tsunami_N_xp{
	meta:
		description = "Backdoor:Linux/Tsunami.N!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {d0 4d e2 14 00 0b e5 18 10 0b e5 14 30 1b e5 00 30 d3 e5 2c 30 0b e5 2c 30 1b e5 } //1
		$a_00_1 = {00 ea 00 30 a0 e3 24 30 0b e5 24 30 1b e5 28 30 0b e5 32 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}