
rule VirTool_Win32_PsExesvcAsrBlock_A{
	meta:
		description = "VirTool:Win32/PsExesvcAsrBlock.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 70 00 73 00 65 00 78 00 65 00 73 00 76 00 63 00 2e 00 65 00 78 00 65 00 00 00 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}