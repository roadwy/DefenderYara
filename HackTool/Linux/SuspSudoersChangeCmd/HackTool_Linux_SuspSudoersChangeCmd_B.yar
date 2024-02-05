
rule HackTool_Linux_SuspSudoersChangeCmd_B{
	meta:
		description = "HackTool:Linux/SuspSudoersChangeCmd.B,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {2d 00 75 00 23 00 2d 00 31 00 } //01 00 
		$a_00_1 = {73 00 75 00 64 00 6f 00 } //00 00 
	condition:
		any of ($a_*)
 
}