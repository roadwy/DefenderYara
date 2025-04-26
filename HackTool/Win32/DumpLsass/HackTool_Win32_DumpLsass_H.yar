
rule HackTool_Win32_DumpLsass_H{
	meta:
		description = "HackTool:Win32/DumpLsass.H,SIGNATURE_TYPE_CMDHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {63 00 6f 00 6d 00 73 00 76 00 63 00 73 00 2e 00 64 00 6c 00 6c 00 } //10 comsvcs.dll
		$a_00_1 = {4d 00 69 00 6e 00 69 00 44 00 75 00 6d 00 70 00 20 00 } //10 MiniDump 
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}