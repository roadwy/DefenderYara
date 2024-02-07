
rule HackTool_Linux_Kerbrute_A_MTB{
	meta:
		description = "HackTool:Linux/Kerbrute.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 65 72 62 72 75 74 65 } //01 00  Kerbrute
		$a_01_1 = {62 72 75 74 65 75 73 65 72 } //01 00  bruteuser
		$a_01_2 = {67 69 74 68 75 62 2e 63 6f 6d 2f 72 6f 70 6e 6f 70 2f 6b 65 72 62 72 75 74 65 2f 63 6d 64 } //01 00  github.com/ropnop/kerbrute/cmd
		$a_01_3 = {2a 63 6f 62 72 61 2e 43 6f 6d 6d 61 6e 64 } //00 00  *cobra.Command
	condition:
		any of ($a_*)
 
}