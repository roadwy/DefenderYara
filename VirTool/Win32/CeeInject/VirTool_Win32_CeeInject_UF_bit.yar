
rule VirTool_Win32_CeeInject_UF_bit{
	meta:
		description = "VirTool:Win32/CeeInject.UF!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b c8 8b 06 8b fb 8a 11 4f 88 10 40 41 85 ff } //1
		$a_01_1 = {8b c8 c1 f9 03 8d 34 39 8b c8 83 e1 07 d2 e2 08 16 40 83 f8 40 7c e3 } //1
		$a_03_2 = {8b 06 03 85 ?? ?? ?? ?? 53 ff 76 fc 50 8b 46 f8 03 85 ?? ?? ?? ?? 50 ff b5 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 0f b7 47 06 ff 85 ?? ?? ?? ?? 83 c6 28 39 85 ?? ?? ?? ?? 7c c8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}