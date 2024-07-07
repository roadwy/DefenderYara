
rule HackTool_Win32_LsassDump_K{
	meta:
		description = "HackTool:Win32/LsassDump.K,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 0a 00 01 00 00 "
		
	strings :
		$a_00_0 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 4e 00 69 00 6e 00 6a 00 61 00 43 00 6f 00 70 00 79 00 } //10 Invoke-NinjaCopy
	condition:
		((#a_00_0  & 1)*10) >=10
 
}