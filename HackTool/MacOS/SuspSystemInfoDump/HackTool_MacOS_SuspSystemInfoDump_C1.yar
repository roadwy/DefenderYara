
rule HackTool_MacOS_SuspSystemInfoDump_C1{
	meta:
		description = "HackTool:MacOS/SuspSystemInfoDump.C1,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_00_0 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 2f 00 75 00 73 00 72 00 2f 00 62 00 69 00 6e 00 2f 00 73 00 77 00 5f 00 76 00 65 00 72 00 73 00 20 00 2d 00 70 00 72 00 6f 00 64 00 75 00 63 00 74 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 } //10 _bs >/dev/null ; /usr/bin/sw_vers -productversion
	condition:
		((#a_00_0  & 1)*10) >=10
 
}