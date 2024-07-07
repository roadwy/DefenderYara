
rule HackTool_Win32_DumpLsass_N{
	meta:
		description = "HackTool:Win32/DumpLsass.N,SIGNATURE_TYPE_CMDHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {73 00 71 00 6c 00 64 00 75 00 6d 00 70 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //10 sqldumper.exe
		$a_00_1 = {30 00 20 00 30 00 78 00 30 00 31 00 } //10 0 0x01
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}