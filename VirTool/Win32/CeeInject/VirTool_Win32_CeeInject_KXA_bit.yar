
rule VirTool_Win32_CeeInject_KXA_bit{
	meta:
		description = "VirTool:Win32/CeeInject.KXA!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 45 fc 8b 4d fc 55 5c 83 f8 7b 74 2c e8 90 01 04 55 6a 79 51 ff 55 f8 90 00 } //01 00 
		$a_03_1 = {f7 e2 8b 7c 24 90 01 01 69 df 90 01 04 01 da 8b 5c 24 90 01 01 8a 1c 0b 89 54 24 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 8a 3c 08 88 7c 24 90 01 01 3a 5c 24 90 01 01 0f 94 c7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}