
rule VirTool_Win32_DelfInject_gen_CR{
	meta:
		description = "VirTool:Win32/DelfInject.gen!CR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 ff d7 66 8b 75 ?? 66 83 c6 02 66 83 fe 3b 72 ?? 66 83 ee 3b eb ?? 8d 45 e8 50 ff d7 } //1
		$a_03_1 = {ff d3 8b f0 81 c6 ?? ?? 00 00 eb ?? ff d3 ff d3 3b f0 77 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}