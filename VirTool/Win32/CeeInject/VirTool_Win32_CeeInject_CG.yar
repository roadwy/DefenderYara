
rule VirTool_Win32_CeeInject_CG{
	meta:
		description = "VirTool:Win32/CeeInject.CG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {d3 c0 59 05 01 01 01 00 05 01 01 01 01 81 f9 35 7c 01 00 72 03 89 45 } //1
		$a_01_1 = {8b 7d fc 33 c0 f3 a4 5e 56 33 c9 66 8b 4e 06 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}