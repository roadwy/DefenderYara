
rule Backdoor_Linux_Tsunami_DT_MTB{
	meta:
		description = "Backdoor:Linux/Tsunami.DT!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d c0 a0 e1 ?? d8 2d e9 ?? b0 4c e2 ?? d0 4d e2 ?? 00 0b e5 ?? 10 0b e5 ?? 30 1b e5 00 30 d3 e5 ?? 30 0b e5 ?? 30 1b e5 54 00 53 e3 ad 00 00 0a ?? 30 1b e5 54 00 53 e3 ?? 00 00 ca ?? 30 1b e5 42 00 53 e3 ?? 00 00 0a ?? 30 1b e5 42 00 53 e3 ?? 00 00 ca ?? 30 1b e5 00 00 53 e3 ?? 00 00 0a ?? 30 1b e5 3f 00 53 e3 ?? 00 00 0a } //1
		$a_03_1 = {44 30 1b e5 6f 00 53 e3 26 00 00 0a ?? 30 1b e5 74 00 53 e3 ?? 00 00 0a ?? 30 1b e5 62 00 53 e3 ?? 00 00 0a ?? 00 00 ea ?? 30 1b e5 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}