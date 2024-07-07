
rule Backdoor_Linux_Tori_A_xp{
	meta:
		description = "Backdoor:Linux/Tori.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {31 ed 49 89 d1 5e 48 89 e2 48 83 e4 f0 50 54 49 c7 c0 50 3b 40 00 48 c7 c1 e0 3a 40 00 48 c7 c7 40 11 40 00 } //1
		$a_00_1 = {b8 ff 72 61 00 55 48 2d f8 72 61 00 48 83 f8 0e 48 89 e5 76 1b b8 00 00 00 00 48 85 c0 74 11 5d bf f8 72 61 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}