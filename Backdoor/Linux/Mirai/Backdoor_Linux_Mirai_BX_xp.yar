
rule Backdoor_Linux_Mirai_BX_xp{
	meta:
		description = "Backdoor:Linux/Mirai.BX!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {41 ef 51 68 2f 48 00 32 20 2f 00 5a 58 80 2f 40 00 3e 22 2f 00 5a 06 81 00 00 05 b4 2f 41 00 46 24 } //1
		$a_00_1 = {81 72 04 b2 80 65 42 30 3b 0a 06 4e fb 00 02 00 0a 19 72 19 ae 1a 16 19 e2 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}