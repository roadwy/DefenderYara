
rule HackTool_Win32_LsassDump_M{
	meta:
		description = "HackTool:Win32/LsassDump.M,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 0a 00 01 00 00 "
		
	strings :
		$a_00_0 = {63 00 72 00 61 00 63 00 6b 00 6d 00 61 00 70 00 65 00 78 00 65 00 63 00 } //10 crackmapexec
	condition:
		((#a_00_0  & 1)*10) >=10
 
}