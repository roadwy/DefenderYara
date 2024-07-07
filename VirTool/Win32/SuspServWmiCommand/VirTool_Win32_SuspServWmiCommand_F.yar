
rule VirTool_Win32_SuspServWmiCommand_F{
	meta:
		description = "VirTool:Win32/SuspServWmiCommand.F,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 } //1 cmd
		$a_00_1 = {4d 00 73 00 69 00 65 00 78 00 65 00 63 00 } //1 Msiexec
		$a_00_2 = {20 00 2f 00 69 00 20 00 68 00 74 00 74 00 70 00 } //1  /i http
		$a_00_3 = {20 00 2f 00 71 00 } //1  /q
		$a_00_4 = {2e 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00 } //-100 .microsoft.com/
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*-100) >=4
 
}