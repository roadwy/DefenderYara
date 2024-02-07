
rule HackTool_Win32_LsassDump_H{
	meta:
		description = "HackTool:Win32/LsassDump.H,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_00_0 = {67 00 73 00 65 00 63 00 64 00 75 00 6d 00 70 00 } //00 00  gsecdump
	condition:
		any of ($a_*)
 
}