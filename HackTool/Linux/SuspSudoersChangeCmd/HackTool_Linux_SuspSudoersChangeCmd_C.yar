
rule HackTool_Linux_SuspSudoersChangeCmd_C{
	meta:
		description = "HackTool:Linux/SuspSudoersChangeCmd.C,SIGNATURE_TYPE_CMDHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {64 00 64 00 20 00 } //01 00 
		$a_00_1 = {6f 00 66 00 6c 00 61 00 67 00 3d 00 61 00 70 00 70 00 65 00 6e 00 64 00 } //01 00 
		$a_00_2 = {6f 00 66 00 3d 00 2f 00 65 00 74 00 63 00 2f 00 73 00 75 00 64 00 6f 00 65 00 72 00 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}