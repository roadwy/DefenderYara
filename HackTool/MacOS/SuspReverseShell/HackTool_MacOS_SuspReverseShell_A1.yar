
rule HackTool_MacOS_SuspReverseShell_A1{
	meta:
		description = "HackTool:MacOS/SuspReverseShell.A1,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {73 00 6f 00 63 00 6b 00 65 00 74 00 [0-ff] 2e 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 [0-ff] 70 00 74 00 79 00 2e 00 73 00 70 00 61 00 77 00 6e 00 28 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}