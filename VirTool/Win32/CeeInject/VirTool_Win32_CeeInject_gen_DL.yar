
rule VirTool_Win32_CeeInject_gen_DL{
	meta:
		description = "VirTool:Win32/CeeInject.gen!DL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 55 fc 8b 42 34 8b 4d fc 03 41 28 89 85 } //01 00 
		$a_03_1 = {79 07 48 0d 00 ff ff ff 40 33 8c 85 90 01 02 ff ff 8b 45 08 03 85 90 01 02 ff ff 88 08 e9 90 00 } //01 00 
		$a_03_2 = {66 8b 51 06 39 95 90 01 02 ff ff 7d 4b 8b 85 90 01 02 ff ff 8b 48 3c 8b 95 90 01 02 ff ff 6b d2 28 03 55 10 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}