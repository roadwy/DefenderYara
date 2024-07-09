
rule VirTool_Win32_CeeInject_KXA_bit{
	meta:
		description = "VirTool:Win32/CeeInject.KXA!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 45 fc 8b 4d fc 55 5c 83 f8 7b 74 2c e8 ?? ?? ?? ?? 55 6a 79 51 ff 55 f8 } //1
		$a_03_1 = {f7 e2 8b 7c 24 ?? 69 df ?? ?? ?? ?? 01 da 8b 5c 24 ?? 8a 1c 0b 89 54 24 ?? 89 44 24 ?? 8b 44 24 ?? 8a 3c 08 88 7c 24 ?? 3a 5c 24 ?? 0f 94 c7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}