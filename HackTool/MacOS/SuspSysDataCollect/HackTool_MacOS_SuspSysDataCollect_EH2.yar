
rule HackTool_MacOS_SuspSysDataCollect_EH2{
	meta:
		description = "HackTool:MacOS/SuspSysDataCollect.EH2,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_00_0 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 69 00 66 00 63 00 6f 00 6e 00 66 00 69 00 67 00 20 00 2d 00 61 00 } //10 _bs >/dev/null ; ifconfig -a
		$a_00_1 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 70 00 66 00 63 00 74 00 6c 00 20 00 2d 00 73 00 20 00 61 00 6c 00 6c 00 } //10 _bs >/dev/null ; pfctl -s all
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10) >=10
 
}