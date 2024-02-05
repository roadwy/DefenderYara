
rule HackTool_Win32_LsassDump_F{
	meta:
		description = "HackTool:Win32/LsassDump.F,SIGNATURE_TYPE_CMDHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {72 00 61 00 72 00 2e 00 65 00 78 00 65 00 20 00 61 00 20 00 } //0a 00 
		$a_00_1 = {6c 00 73 00 61 00 73 00 73 00 2e 00 64 00 6d 00 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}