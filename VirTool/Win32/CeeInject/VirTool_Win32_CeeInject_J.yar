
rule VirTool_Win32_CeeInject_J{
	meta:
		description = "VirTool:Win32/CeeInject.J,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 64 a1 30 00 00 00 0f b6 40 02 0b c0 74 02 c9 c3 58 0f 31 83 c2 01 89 55 f0 0f 31 39 55 f0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}