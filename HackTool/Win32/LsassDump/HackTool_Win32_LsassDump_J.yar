
rule HackTool_Win32_LsassDump_J{
	meta:
		description = "HackTool:Win32/LsassDump.J,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 0a 00 01 00 00 "
		
	strings :
		$a_00_0 = {4d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 } //10 Mimikatz
	condition:
		((#a_00_0  & 1)*10) >=10
 
}