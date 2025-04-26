
rule HackTool_MacOS_SuspSysDataCollect_GH1{
	meta:
		description = "HackTool:MacOS/SuspSysDataCollect.GH1,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_00_0 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 74 00 6f 00 70 00 20 00 2d 00 6e 00 20 00 32 00 30 00 20 00 2d 00 6c 00 20 00 31 00 } //10 _bs >/dev/null ; top -n 20 -l 1
		$a_00_1 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 6c 00 73 00 20 00 2f 00 75 00 73 00 72 00 2f 00 6c 00 69 00 62 00 2f 00 63 00 72 00 6f 00 6e 00 2f 00 74 00 61 00 62 00 73 00 } //10 _bs >/dev/null ; ls /usr/lib/cron/tabs
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10) >=10
 
}