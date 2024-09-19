
rule HackTool_Linux_Fscan_A_MTB{
	meta:
		description = "HackTool:Linux/Fscan.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 68 61 64 6f 77 31 6e 67 2f 66 73 63 61 6e } //1 shadow1ng/fscan
		$a_01_1 = {50 6c 75 67 69 6e 73 2e 65 78 70 6c 6f 69 74 } //1 Plugins.exploit
		$a_01_2 = {65 78 70 6c 6f 69 74 2d 64 62 } //1 exploit-db
		$a_01_3 = {68 61 63 6b 67 6f 76 } //1 hackgov
		$a_01_4 = {50 6c 75 67 69 6e 73 2e 42 72 75 74 65 6c 69 73 74 } //1 Plugins.Brutelist
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}