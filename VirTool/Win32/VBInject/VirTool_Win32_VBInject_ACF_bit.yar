
rule VirTool_Win32_VBInject_ACF_bit{
	meta:
		description = "VirTool:Win32/VBInject.ACF!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ba 04 00 00 00 b8 ?? ?? ?? ?? 31 04 0f f8 19 d1 7d ee 83 c4 0c ff e7 } //1
		$a_01_1 = {be 00 10 40 00 ad 83 f8 00 74 fa 81 38 55 8b ec 83 75 f2 bb eb 0c 56 8d 43 39 58 04 75 e7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}