
rule VirTool_Win32_DelfInject_gen_CR{
	meta:
		description = "VirTool:Win32/DelfInject.gen!CR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 ff d7 66 8b 75 90 01 01 66 83 c6 02 66 83 fe 3b 72 90 01 01 66 83 ee 3b eb 90 01 01 8d 45 e8 50 ff d7 90 00 } //01 00 
		$a_03_1 = {ff d3 8b f0 81 c6 90 01 02 00 00 eb 90 01 01 ff d3 ff d3 3b f0 77 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}