
rule VirTool_Win32_CeeInject_BAD_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BAD!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 8b 45 08 c1 e0 04 03 45 0c 8b 4d 08 03 4d 10 33 c1 8b 90 01 01 08 c1 90 01 01 05 03 90 01 01 14 33 90 01 01 5d c3 90 00 } //01 00 
		$a_03_1 = {55 8b ec 8b 45 08 c1 e0 04 03 45 0c 8b 4d 08 03 4d 14 33 c1 8b 90 01 01 08 c1 90 01 01 05 03 90 01 01 10 33 90 00 } //01 00 
		$a_01_2 = {89 55 fc 8b 45 fc c1 e0 04 03 45 e4 8b 4d fc 03 4d f4 33 c1 8b 55 fc c1 ea 05 03 55 e0 33 c2 } //00 00 
	condition:
		any of ($a_*)
 
}