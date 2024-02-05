
rule Backdoor_Linux_Gafgyt_Q_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.Q!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {10 40 2d e9 21 01 90 01 01 ef 01 0a 70 e3 00 40 a0 e1 03 00 90 01 04 ff eb 00 30 64 e2 00 30 80 e5 00 40 e0 e3 04 00 a0 e1 10 80 bd e8 90 00 } //01 00 
		$a_01_1 = {4b 49 4c 4c 41 54 54 4b } //01 00 
		$a_01_2 = {62 69 67 62 6f 74 73 } //01 00 
		$a_01_3 = {55 44 50 52 41 57 } //00 00 
	condition:
		any of ($a_*)
 
}