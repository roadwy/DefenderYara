
rule HackTool_MacOS_SuspCodeExecution_PC{
	meta:
		description = "HackTool:MacOS/SuspCodeExecution.PC,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_00_0 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 75 00 70 00 74 00 69 00 6d 00 65 00 } //10 _bs >/dev/null ; uptime
		$a_00_1 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 73 00 6c 00 65 00 65 00 70 00 20 00 } //10 _bs >/dev/null ; sleep 
		$a_00_2 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 70 00 69 00 6e 00 67 00 20 00 77 00 77 00 77 00 2e 00 } //10 _bs >/dev/null ; ping www.
		$a_00_3 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 77 00 68 00 6f 00 20 00 2d 00 61 00 } //10 _bs >/dev/null ; who -a
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=10
 
}