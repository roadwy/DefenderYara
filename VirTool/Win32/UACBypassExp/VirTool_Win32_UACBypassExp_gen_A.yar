
rule VirTool_Win32_UACBypassExp_gen_A{
	meta:
		description = "VirTool:Win32/UACBypassExp.gen!A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_00_0 = {2e 00 65 00 78 00 65 00 00 00 } //1
		$a_00_1 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 } //-100 \Windows\
		$a_00_2 = {5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 } //-100 \Program Files
		$a_00_3 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 } //-100 \Windows Defender
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*-100+(#a_00_2  & 1)*-100+(#a_00_3  & 1)*-100) >=1
 
}