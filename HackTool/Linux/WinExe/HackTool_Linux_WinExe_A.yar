
rule HackTool_Linux_WinExe_A{
	meta:
		description = "HackTool:Linux/WinExe.A,SIGNATURE_TYPE_CMDHSTR_EXT,1a 00 1a 00 04 00 00 "
		
	strings :
		$a_00_0 = {77 00 69 00 6e 00 65 00 78 00 65 00 } //20 winexe
		$a_00_1 = {2d 00 75 00 } //5 -u
		$a_00_2 = {2f 00 2f 00 } //1 //
		$a_00_3 = {64 00 61 00 74 00 61 00 68 00 75 00 62 00 } //-100 datahub
	condition:
		((#a_00_0  & 1)*20+(#a_00_1  & 1)*5+(#a_00_2  & 1)*1+(#a_00_3  & 1)*-100) >=26
 
}