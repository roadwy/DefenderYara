
rule VirTool_Win32_CeeInject_E{
	meta:
		description = "VirTool:Win32/CeeInject.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 62 69 65 64 6c 6c 2e 64 6c 6c } //01 00  sbiedll.dll
		$a_00_1 = {61 70 69 5f 6c 6f 67 2e 64 6c 6c } //01 00  api_log.dll
		$a_03_2 = {e9 00 00 00 00 6a 0e 68 90 01 04 e8 90 01 04 59 a3 90 01 04 59 c3 e9 00 00 00 00 6a 90 01 01 68 90 01 04 e8 90 01 04 59 a3 90 01 04 59 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}