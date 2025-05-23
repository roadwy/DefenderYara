
rule HackTool_Linux_SuspUnixReShellCmd_A{
	meta:
		description = "HackTool:Linux/SuspUnixReShellCmd.A,SIGNATURE_TYPE_CMDHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_00_0 = {77 00 68 00 69 00 6c 00 65 00 } //1 while
		$a_00_1 = {65 00 78 00 70 00 6f 00 72 00 74 00 } //1 export
		$a_02_2 = {65 00 76 00 61 00 6c 00 20 00 24 00 28 00 77 00 68 00 6f 00 69 00 73 00 20 00 2d 00 68 00 20 00 [0-20] 20 00 2d 00 70 00 } //10
		$a_00_3 = {31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 } //-50 127.0.0.1
		$a_00_4 = {6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 } //-50 localhost
		$a_00_5 = {30 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 } //-50 0.0.0.0
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*10+(#a_00_3  & 1)*-50+(#a_00_4  & 1)*-50+(#a_00_5  & 1)*-50) >=12
 
}