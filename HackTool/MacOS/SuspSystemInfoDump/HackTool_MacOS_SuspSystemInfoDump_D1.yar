
rule HackTool_MacOS_SuspSystemInfoDump_D1{
	meta:
		description = "HackTool:MacOS/SuspSystemInfoDump.D1,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_00_0 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 68 00 6f 00 73 00 74 00 6e 00 61 00 6d 00 65 00 } //10 _bs >/dev/null ; hostname
		$a_00_1 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 61 00 72 00 70 00 20 00 2d 00 61 00 } //10 _bs >/dev/null ; arp -a
		$a_00_2 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 6e 00 65 00 74 00 73 00 74 00 61 00 74 00 20 00 2d 00 6e 00 6c 00 74 00 75 00 } //10 _bs >/dev/null ; netstat -nltu
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10) >=10
 
}