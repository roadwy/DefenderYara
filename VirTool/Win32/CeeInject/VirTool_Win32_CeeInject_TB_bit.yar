
rule VirTool_Win32_CeeInject_TB_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TB!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5f 5f 6a 40 68 00 30 00 00 68 00 64 01 00 6a 00 e8 } //1
		$a_03_1 = {8b df b9 e4 02 00 00 ba cf 00 00 00 e9 90 01 04 0f 85 90 01 04 ff d3 90 90 81 c4 e4 02 00 00 e9 90 01 04 8a 06 32 c2 88 07 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}