
rule VirTool_Win32_CeeInject_DZ{
	meta:
		description = "VirTool:Win32/CeeInject.DZ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {a1 20 dc 41 00 30 1c 30 83 c4 08 83 ee 01 0f 85 6b ff ff ff ff 15 20 dc 41 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}