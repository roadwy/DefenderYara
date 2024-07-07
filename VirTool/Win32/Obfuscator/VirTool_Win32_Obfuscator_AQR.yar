
rule VirTool_Win32_Obfuscator_AQR{
	meta:
		description = "VirTool:Win32/Obfuscator.AQR,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 06 83 c6 04 8b 5d ee 31 d8 89 07 83 c7 04 49 85 c9 75 ec 8b 45 e2 66 b8 00 00 66 bb 4d 5a 66 39 18 74 07 2d 00 10 00 00 } //1
		$a_01_1 = {8b 06 83 c6 04 8b 5d ee 31 d8 89 07 83 c7 04 49 85 c9 75 ec } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}