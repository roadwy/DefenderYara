
rule Backdoor_Linux_Tsunami_DT_MTB{
	meta:
		description = "Backdoor:Linux/Tsunami.DT!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0d c0 a0 e1 90 01 01 d8 2d e9 90 01 01 b0 4c e2 90 01 01 d0 4d e2 90 01 01 00 0b e5 90 01 01 10 0b e5 90 01 01 30 1b e5 00 30 d3 e5 90 01 01 30 0b e5 90 01 01 30 1b e5 54 00 53 e3 ad 00 00 0a 90 01 01 30 1b e5 54 00 53 e3 90 01 01 00 00 ca 90 01 01 30 1b e5 42 00 53 e3 90 01 01 00 00 0a 90 01 01 30 1b e5 42 00 53 e3 90 01 01 00 00 ca 90 01 01 30 1b e5 00 00 53 e3 90 01 01 00 00 0a 90 01 01 30 1b e5 3f 00 53 e3 90 01 01 00 00 0a 90 00 } //01 00 
		$a_03_1 = {44 30 1b e5 6f 00 53 e3 26 00 00 0a 90 01 01 30 1b e5 74 00 53 e3 90 01 01 00 00 0a 90 01 01 30 1b e5 62 00 53 e3 90 01 01 00 00 0a 90 01 01 00 00 ea 90 01 01 30 1b e5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}