
rule VirTool_Win32_CeeInject_AMT_bit{
	meta:
		description = "VirTool:Win32/CeeInject.AMT!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {56 68 00 30 00 00 50 53 ff 15 90 01 03 00 89 85 90 01 03 ff 90 00 } //01 00 
		$a_01_1 = {68 00 de 44 00 50 ff d7 } //01 00 
		$a_03_2 = {8a c3 32 85 90 02 30 88 84 90 01 04 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}