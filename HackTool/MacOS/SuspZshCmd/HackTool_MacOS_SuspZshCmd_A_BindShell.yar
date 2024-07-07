
rule HackTool_MacOS_SuspZshCmd_A_BindShell{
	meta:
		description = "HackTool:MacOS/SuspZshCmd.A!BindShell,SIGNATURE_TYPE_CMDHSTR_EXT,ffffffc8 00 46 00 07 00 00 "
		
	strings :
		$a_00_0 = {7a 00 73 00 68 00 } //10 zsh
		$a_00_1 = {7a 00 6d 00 6f 00 64 00 6c 00 6f 00 61 00 64 00 } //20 zmodload
		$a_00_2 = {7a 00 73 00 68 00 2f 00 6e 00 65 00 74 00 2f 00 74 00 63 00 70 00 } //20 zsh/net/tcp
		$a_02_3 = {7a 00 74 00 63 00 70 00 20 00 90 02 20 2d 00 6c 00 90 00 } //20
		$a_00_4 = {6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 } //-50 localhost
		$a_00_5 = {31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 } //-50 127.0.0.1
		$a_00_6 = {30 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 } //-50 0.0.0.0
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*20+(#a_00_2  & 1)*20+(#a_02_3  & 1)*20+(#a_00_4  & 1)*-50+(#a_00_5  & 1)*-50+(#a_00_6  & 1)*-50) >=70
 
}