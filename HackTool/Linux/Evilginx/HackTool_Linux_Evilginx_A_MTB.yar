
rule HackTool_Linux_Evilginx_A_MTB{
	meta:
		description = "HackTool:Linux/Evilginx.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 67 72 65 74 7a 6b 79 2f 65 76 69 6c 67 69 6e 78 } //01 00  kgretzky/evilginx
		$a_01_1 = {68 61 6e 64 6c 65 50 68 69 73 68 6c 65 74 73 } //01 00  handlePhishlets
		$a_01_2 = {50 68 69 73 68 4c 75 72 65 } //01 00  PhishLure
		$a_01_3 = {47 65 74 50 68 69 73 68 48 6f 73 74 73 } //00 00  GetPhishHosts
	condition:
		any of ($a_*)
 
}