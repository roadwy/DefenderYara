
rule HackTool_Linux_Pspy_A_MTB{
	meta:
		description = "HackTool:Linux/Pspy.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 6f 6d 69 6e 69 63 62 72 65 75 6b 65 72 2f 70 73 70 79 2f 69 6e 74 65 72 6e 61 6c 2f 70 73 70 79 } //01 00  dominicbreuker/pspy/internal/pspy
		$a_01_1 = {2a 70 73 70 79 2e 4c 6f 67 67 65 72 } //01 00  *pspy.Logger
		$a_01_2 = {2a 70 73 70 79 2e 50 53 53 63 61 6e 6e 65 72 } //01 00  *pspy.PSScanner
		$a_01_3 = {2a 70 73 70 79 2e 46 53 57 61 74 63 68 65 72 } //01 00  *pspy.FSWatcher
		$a_01_4 = {64 6f 6d 69 6e 69 63 62 72 65 75 6b 65 72 2f 70 73 70 79 2f 69 6e 74 65 72 6e 61 6c 2f 63 6f 6e 66 69 67 } //00 00  dominicbreuker/pspy/internal/config
	condition:
		any of ($a_*)
 
}