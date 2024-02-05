
rule HackTool_Win32_LsassDump_L{
	meta:
		description = "HackTool:Win32/LsassDump.L,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_00_0 = {70 00 79 00 70 00 79 00 6b 00 61 00 74 00 7a 00 } //00 00 
	condition:
		any of ($a_*)
 
}