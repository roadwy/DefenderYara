
rule VirTool_Win32_CeeInject_gen_DB{
	meta:
		description = "VirTool:Win32/CeeInject.gen!DB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 04 33 43 39 fb 72 f3 } //01 00 
		$a_03_1 = {8b 47 28 03 05 90 01 04 89 85 90 01 04 8d 85 90 01 04 89 44 24 04 a1 90 01 04 89 04 24 ff 15 90 00 } //01 00 
		$a_00_2 = {6e 65 74 20 73 74 6f 70 20 4d 73 4d 70 53 76 63 } //00 00  net stop MsMpSvc
	condition:
		any of ($a_*)
 
}