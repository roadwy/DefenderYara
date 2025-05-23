
rule HackTool_MacOS_SuspPythonCmd_A_ReverseShellSsl{
	meta:
		description = "HackTool:MacOS/SuspPythonCmd.A!ReverseShellSsl,SIGNATURE_TYPE_CMDHSTR_EXT,ffffffc8 00 42 00 0f 00 00 "
		
	strings :
		$a_02_0 = {70 00 79 00 74 00 68 00 6f 00 6e 00 [0-20] 2d 00 63 00 [0-20] 69 00 6d 00 70 00 6f 00 72 00 74 00 } //10
		$a_02_1 = {73 00 75 00 62 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 2e 00 63 00 61 00 6c 00 6c 00 [0-02] 28 00 } //10
		$a_02_2 = {73 00 75 00 62 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 2e 00 70 00 6f 00 70 00 65 00 6e 00 [0-02] 28 00 } //10
		$a_02_3 = {2f 00 62 00 69 00 6e 00 2f 00 [0-04] 73 00 68 00 } //10
		$a_00_4 = {73 00 68 00 65 00 6c 00 6c 00 3d 00 74 00 72 00 75 00 65 00 } //10 shell=true
		$a_02_5 = {6f 00 73 00 2e 00 73 00 65 00 74 00 75 00 69 00 64 00 [0-02] 28 00 [0-02] 30 00 } //15
		$a_00_6 = {61 00 66 00 5f 00 69 00 6e 00 65 00 74 00 } //5 af_inet
		$a_00_7 = {73 00 6f 00 63 00 6b 00 5f 00 73 00 74 00 72 00 65 00 61 00 6d 00 } //5 sock_stream
		$a_02_8 = {63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 [0-02] 28 00 } //5
		$a_00_9 = {77 00 72 00 61 00 70 00 5f 00 73 00 6f 00 63 00 6b 00 65 00 74 00 } //20 wrap_socket
		$a_00_10 = {64 00 75 00 70 00 32 00 } //1 dup2
		$a_00_11 = {73 00 75 00 62 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 2e 00 70 00 69 00 70 00 65 00 } //1 subprocess.pipe
		$a_00_12 = {6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 } //-50 localhost
		$a_00_13 = {31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 } //-50 127.0.0.1
		$a_00_14 = {30 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 } //-50 0.0.0.0
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*10+(#a_02_3  & 1)*10+(#a_00_4  & 1)*10+(#a_02_5  & 1)*15+(#a_00_6  & 1)*5+(#a_00_7  & 1)*5+(#a_02_8  & 1)*5+(#a_00_9  & 1)*20+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*-50+(#a_00_13  & 1)*-50+(#a_00_14  & 1)*-50) >=66
 
}