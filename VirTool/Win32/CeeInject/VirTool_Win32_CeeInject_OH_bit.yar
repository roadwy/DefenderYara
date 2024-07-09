
rule VirTool_Win32_CeeInject_OH_bit{
	meta:
		description = "VirTool:Win32/CeeInject.OH!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {ba 40 80 40 00 03 55 8c a1 74 2a 44 00 03 45 8c 8a 0a 88 08 } //1
		$a_03_1 = {74 78 8b 0d ?? ?? ?? ?? 33 d2 8a 51 01 83 ea 4c 85 d2 } //1
		$a_01_2 = {8b 55 fc a1 30 e0 43 00 89 42 6c 8b 4d fc 51 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}