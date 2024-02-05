
rule Backdoor_Linux_SAgnt_A_xp{
	meta:
		description = "Backdoor:Linux/SAgnt.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {31 ed 49 89 d1 5e 48 89 e2 48 83 e4 f0 50 54 48 c7 c7 95 01 40 00 48 c7 c1 58 01 40 00 49 c7 c0 f8 8d 43 00 } //01 00 
		$a_00_1 = {41 54 55 49 89 f4 53 31 f6 48 89 fb 40 b5 ff e8 7e 07 00 00 31 f6 48 89 df } //01 00 
		$a_00_2 = {31 c0 4c 89 ef 48 83 c9 ff f2 ae f7 d9 48 63 d9 48 89 df e8 82 ff ff ff 4c 89 e9 48 89 04 24 48 89 c7 ba 6a 8e 43 00 48 89 de 31 c0 } //00 00 
	condition:
		any of ($a_*)
 
}