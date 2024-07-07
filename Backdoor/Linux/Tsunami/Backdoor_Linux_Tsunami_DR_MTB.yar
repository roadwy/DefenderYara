
rule Backdoor_Linux_Tsunami_DR_MTB{
	meta:
		description = "Backdoor:Linux/Tsunami.DR!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d c0 a0 e1 90 01 02 2d e9 90 01 02 4c e2 90 01 02 4d e2 14 00 0b e5 18 10 0b e5 14 30 1b e5 00 30 d3 e5 40 30 0b e5 40 30 1b e5 54 00 53 e3 90 01 02 00 0a 40 30 1b e5 54 00 53 e3 10 00 00 ca 40 30 1b e5 42 00 53 e3 90 01 02 00 0a 40 30 1b e5 42 00 53 e3 06 00 00 ca 40 30 1b e5 00 00 53 e3 90 01 02 00 0a 40 30 1b e5 3f 00 53 e3 90 01 02 00 0a 90 00 } //1
		$a_03_1 = {10 00 1b e5 90 01 02 00 eb 00 30 a0 e1 03 20 a0 e1 10 30 1b e5 03 30 82 e0 90 01 02 43 e2 00 30 d3 e5 0a 00 53 e3 90 01 02 ff 0a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}