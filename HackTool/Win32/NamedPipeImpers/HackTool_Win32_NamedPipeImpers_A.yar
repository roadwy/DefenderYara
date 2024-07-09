
rule HackTool_Win32_NamedPipeImpers_A{
	meta:
		description = "HackTool:Win32/NamedPipeImpers.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 65 00 63 00 68 00 6f 00 20 00 90 2f 10 00 20 00 3e 00 20 00 5c 00 5c 00 2e 00 5c 00 70 00 69 00 70 00 65 00 5c 00 90 2f 10 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule HackTool_Win32_NamedPipeImpers_A_2{
	meta:
		description = "HackTool:Win32/NamedPipeImpers.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 43 00 20 00 [0-a0] 65 00 63 00 68 00 6f 00 20 00 90 2f 10 00 20 00 3e 00 20 00 5c 00 5c 00 2e 00 5c 00 70 00 69 00 70 00 65 00 5c 00 90 2f 10 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}