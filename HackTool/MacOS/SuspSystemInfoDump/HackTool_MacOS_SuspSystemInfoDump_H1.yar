
rule HackTool_MacOS_SuspSystemInfoDump_H1{
	meta:
		description = "HackTool:MacOS/SuspSystemInfoDump.H1,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_00_0 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 5f 00 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 72 00 20 00 73 00 70 00 70 00 72 00 69 00 6e 00 74 00 65 00 72 00 73 00 64 00 61 00 74 00 61 00 74 00 79 00 70 00 65 00 } //10 _bs >/dev/null ; system_profiler spprintersdatatype
		$a_00_1 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 5f 00 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 72 00 20 00 73 00 70 00 62 00 6c 00 75 00 65 00 74 00 6f 00 6f 00 74 00 68 00 64 00 61 00 74 00 61 00 74 00 79 00 70 00 65 00 } //10 _bs >/dev/null ; system_profiler spbluetoothdatatype
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10) >=10
 
}