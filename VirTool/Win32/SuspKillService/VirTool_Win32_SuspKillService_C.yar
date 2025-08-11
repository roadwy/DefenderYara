
rule VirTool_Win32_SuspKillService_C{
	meta:
		description = "VirTool:Win32/SuspKillService.C,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {6e 00 75 00 6c 00 20 00 26 00 20 00 6e 00 65 00 74 00 20 00 73 00 74 00 6f 00 70 00 [0-18] 20 00 26 00 } //1
		$a_02_1 = {6e 75 6c 20 26 20 6e 65 74 20 73 74 6f 70 [0-18] 20 26 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}