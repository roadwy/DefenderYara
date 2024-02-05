
rule VirTool_Win32_CeeInject_TW_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TW!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c3 8a 00 90 01 07 34 28 8b 15 90 01 04 03 d3 88 02 90 00 } //01 00 
		$a_01_1 = {8d 43 01 bf 75 00 00 00 33 d2 f7 f7 8b c1 03 c3 88 10 } //00 00 
	condition:
		any of ($a_*)
 
}