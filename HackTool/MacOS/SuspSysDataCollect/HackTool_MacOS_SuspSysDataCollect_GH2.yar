
rule HackTool_MacOS_SuspSysDataCollect_GH2{
	meta:
		description = "HackTool:MacOS/SuspSysDataCollect.GH2,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_00_0 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 65 00 78 00 70 00 6f 00 72 00 74 00 20 00 68 00 69 00 73 00 74 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 3d 00 69 00 67 00 6e 00 6f 00 72 00 65 00 73 00 70 00 61 00 63 00 65 00 20 00 3b 00 20 00 65 00 6e 00 76 00 20 00 7c 00 20 00 67 00 72 00 65 00 70 00 20 00 2d 00 71 00 20 00 68 00 69 00 73 00 74 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 } //10 _bs >/dev/null ; export histcontrol=ignorespace ; env | grep -q histcontrol
		$a_02_1 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 64 00 69 00 67 00 20 00 2b 00 73 00 68 00 6f 00 72 00 74 00 20 00 6d 00 79 00 69 00 70 00 2e 00 6f 00 70 00 65 00 6e 00 64 00 6e 00 73 00 2e 00 63 00 6f 00 6d 00 20 00 [0-20] 2e 00 6f 00 70 00 65 00 6e 00 64 00 6e 00 73 00 2e 00 63 00 6f 00 6d 00 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10) >=10
 
}