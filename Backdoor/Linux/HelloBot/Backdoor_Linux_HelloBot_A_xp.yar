
rule Backdoor_Linux_HelloBot_A_xp{
	meta:
		description = "Backdoor:Linux/HelloBot.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 68 65 6c 6c 54 61 73 6b } //1 ShellTask
		$a_00_1 = {48 49 53 54 46 49 4c 45 } //1 HISTFILE
		$a_00_2 = {66 75 63 6b 20 79 6f 75 } //1 fuck you
		$a_00_3 = {69 6e 73 74 61 6c 6c 5f 70 61 74 68 5f 62 61 6b } //1 install_path_bak
		$a_00_4 = {65 63 66 61 66 65 61 62 36 65 65 37 64 36 34 32 } //1 ecfafeab6ee7d642
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}