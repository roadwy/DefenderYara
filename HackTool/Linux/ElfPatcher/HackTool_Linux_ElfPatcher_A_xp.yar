
rule HackTool_Linux_ElfPatcher_A_xp{
	meta:
		description = "HackTool:Linux/ElfPatcher.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {69 6e 66 65 63 74 5f 6d 65 5f 62 61 62 79 28 29 29 20 3a 20 25 73 } //2 infect_me_baby()) : %s
		$a_01_1 = {49 6e 66 65 63 74 69 6e 67 20 68 6f 73 74 20 66 69 6c 65 20 61 74 20 6f 66 66 73 65 74 } //1 Infecting host file at offset
		$a_01_2 = {63 79 6e 65 6f 78 2e 74 6d 70 } //1 cyneox.tmp
		$a_01_3 = {75 73 61 67 65 3a 25 73 20 66 69 6c 65 5f 74 6f 5f 69 6e 66 65 63 74 } //1 usage:%s file_to_infect
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}