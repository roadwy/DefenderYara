
rule VirTool_Win32_CeeInject_gen_KK{
	meta:
		description = "VirTool:Win32/CeeInject.gen!KK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 86 57 0d 00 68 88 4e 0d 00 e8 1a 00 00 00 89 45 fc 68 fa 8b 34 00 68 88 4e 0d 00 e8 08 00 00 00 89 45 f8 e9 b5 00 00 00 } //01 00 
		$a_03_1 = {99 f7 fe 8b 75 f8 8a 84 95 90 01 02 ff ff 30 06 ff 45 14 8b 45 14 3b 45 10 72 95 90 00 } //01 00 
		$a_01_2 = {8d 72 01 8b 54 24 10 8a 02 88 01 41 42 4e 75 f7 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_gen_KK_2{
	meta:
		description = "VirTool:Win32/CeeInject.gen!KK,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 86 57 0d 00 68 88 4e 0d 00 e8 1a 00 00 00 89 45 fc 68 fa 8b 34 00 68 88 4e 0d 00 e8 08 00 00 00 89 45 f8 e9 90 01 04 55 8b ec 53 56 57 51 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}