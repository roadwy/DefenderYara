
rule HackTool_Win32_LsassDump_I{
	meta:
		description = "HackTool:Win32/LsassDump.I,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 0a 00 01 00 00 "
		
	strings :
		$a_00_0 = {70 00 77 00 64 00 75 00 6d 00 70 00 78 00 } //10 pwdumpx
	condition:
		((#a_00_0  & 1)*10) >=10
 
}