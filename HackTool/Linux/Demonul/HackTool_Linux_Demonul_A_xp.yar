
rule HackTool_Linux_Demonul_A_xp{
	meta:
		description = "HackTool:Linux/Demonul.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 6f 72 6e 69 6d 20 64 65 6d 6f 6e 75 6c } //2 Pornim demonul
		$a_01_1 = {72 65 61 64 79 20 70 69 64 20 69 73 3a 20 25 64 } //1 ready pid is: %d
		$a_01_2 = {61 6e 61 63 72 6f 6e 64 2e 63 } //1 anacrond.c
		$a_01_3 = {4e 55 20 70 6f 63 69 2c 20 62 79 65 21 } //1 NU poci, bye!
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}