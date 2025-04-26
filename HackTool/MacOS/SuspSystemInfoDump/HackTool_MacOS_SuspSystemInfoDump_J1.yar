
rule HackTool_MacOS_SuspSystemInfoDump_J1{
	meta:
		description = "HackTool:MacOS/SuspSystemInfoDump.J1,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_00_0 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 64 00 66 00 20 00 2d 00 61 00 68 00 } //10 _bs >/dev/null ; df -ah
	condition:
		((#a_00_0  & 1)*10) >=10
 
}