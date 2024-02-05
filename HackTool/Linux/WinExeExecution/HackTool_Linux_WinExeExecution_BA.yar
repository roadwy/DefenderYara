
rule HackTool_Linux_WinExeExecution_BA{
	meta:
		description = "HackTool:Linux/WinExeExecution.BA,SIGNATURE_TYPE_CMDHSTR_EXT,08 00 08 00 07 00 00 05 00 "
		
	strings :
		$a_00_0 = {77 00 69 00 6e 00 65 00 78 00 65 00 } //02 00 
		$a_00_1 = {2f 00 2f 00 } //01 00 
		$a_00_2 = {2d 00 75 00 20 00 } //01 00 
		$a_00_3 = {2d 00 2d 00 75 00 73 00 65 00 72 00 3d 00 } //01 00 
		$a_00_4 = {2d 00 2d 00 72 00 75 00 6e 00 61 00 73 00 3d 00 } //01 00 
		$a_00_5 = {2d 00 61 00 20 00 } //01 00 
		$a_00_6 = {2d 00 2d 00 61 00 75 00 74 00 68 00 65 00 6e 00 74 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 2d 00 66 00 69 00 6c 00 65 00 3d 00 } //00 00 
	condition:
		any of ($a_*)
 
}