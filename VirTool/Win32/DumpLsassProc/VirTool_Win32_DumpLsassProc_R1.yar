
rule VirTool_Win32_DumpLsassProc_R1{
	meta:
		description = "VirTool:Win32/DumpLsassProc.R1,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //1 powershell.exe
		$a_00_1 = {72 00 64 00 72 00 6c 00 65 00 61 00 6b 00 64 00 69 00 61 00 67 00 2e 00 65 00 78 00 65 00 } //1 rdrleakdiag.exe
		$a_02_2 = {2f 00 70 00 [0-08] 28 00 47 00 65 00 74 00 2d 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 6c 00 73 00 61 00 73 00 73 00 29 00 2e 00 49 00 64 00 20 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}