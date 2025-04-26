
rule VirTool_Win32_Patcher_C{
	meta:
		description = "VirTool:Win32/Patcher.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 c0 83 c0 18 64 8b 08 89 e2 83 c0 18 8b 04 08 b9 02 00 00 00 0f b6 04 01 83 c0 17 03 02 ff e0 76 ?? 13 bb 64 c3 90 90 00 } //1
		$a_01_1 = {8b 42 f6 8b 5a fa 8a 52 fe 31 c9 30 10 40 41 31 ca 39 d9 76 f6 59 58 8b 50 ea 89 11 8b 50 ee 89 51 04 58 9d ff e0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}