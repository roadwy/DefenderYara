
rule Backdoor_Linux_Gafgyt_I_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.I!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {00 94 80 00 00 0d c0 a0 e1 00 d8 2d e9 04 b0 4c e2 44 d0 4d e2 44 00 0b e5 48 10 0b e5 4c 20 0b e5 4c 30 1b e5 00 00 53 e3 02 00 00 1a 00 10 } //1
		$a_00_1 = {3c 40 81 e5 40 40 81 e5 d8 01 9f e5 1c fb ff eb 35 5c a0 e3 01 3a 8d e2 01 1a 8d e2 38 00 83 e5 34 10 81 e2 08 00 a0 e1 10 20 a0 e3 b6 53 c3 e1 e6 fa ff eb 01 00 70 e3 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}