
rule VirTool_Win32_ExecutionFromADS_B{
	meta:
		description = "VirTool:Win32/ExecutionFromADS.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_02_0 = {5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 61 00 69 00 5f 00 61 00 6c 00 74 00 65 00 72 00 6e 00 61 00 74 00 65 00 5f 00 73 00 74 00 72 00 65 00 61 00 6d 00 5f 00 [0-20] 3a 00 61 00 69 00 2d 00 } //3
	condition:
		((#a_02_0  & 1)*3) >=3
 
}