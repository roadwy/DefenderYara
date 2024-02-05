
rule VirTool_Win32_CeeInject_BDP_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BDP!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 89 45 fc 8b 5d fc 90 02 10 81 c3 33 36 00 00 90 02 10 ff e3 90 0a 20 00 34 90 01 01 88 02 90 00 } //01 00 
		$a_03_1 = {54 6a 40 68 90 01 04 57 e8 90 01 03 ff 90 0a 20 00 b8 90 01 04 e8 90 01 03 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}