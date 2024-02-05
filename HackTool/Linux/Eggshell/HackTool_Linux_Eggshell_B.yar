
rule HackTool_Linux_Eggshell_B{
	meta:
		description = "HackTool:Linux/Eggshell.B,SIGNATURE_TYPE_CMDHSTR_EXT,16 00 16 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {76 00 61 00 72 00 } //0a 00 
		$a_00_1 = {37 00 37 00 37 00 } //0a 00 
		$a_00_2 = {2f 00 74 00 6d 00 70 00 2f 00 65 00 73 00 70 00 6c 00 2e 00 70 00 79 00 } //00 00 
	condition:
		any of ($a_*)
 
}