
rule HackTool_MacOS_SuspNetcatCmd_A_BindShell{
	meta:
		description = "HackTool:MacOS/SuspNetcatCmd.A!BindShell,SIGNATURE_TYPE_CMDHSTR_EXT,ffffffc8 00 32 00 06 00 00 "
		
	strings :
		$a_00_0 = {6d 00 6b 00 66 00 69 00 66 00 6f 00 } //10 mkfifo
		$a_02_1 = {6e 00 63 00 20 00 90 02 20 2d 00 6c 00 90 00 } //30
		$a_00_2 = {73 00 68 00 20 00 } //10 sh 
		$a_00_3 = {6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 } //-50 localhost
		$a_00_4 = {31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 } //-50 127.0.0.1
		$a_00_5 = {30 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 } //-50 0.0.0.0
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*30+(#a_00_2  & 1)*10+(#a_00_3  & 1)*-50+(#a_00_4  & 1)*-50+(#a_00_5  & 1)*-50) >=50
 
}