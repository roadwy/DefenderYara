
rule VirTool_Win32_CeeInject_UI_bit{
	meta:
		description = "VirTool:Win32/CeeInject.UI!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 17 8d 52 01 80 f1 8b 80 c1 5a 80 f1 11 80 e9 15 88 4a ff 4e 75 e8 } //1
		$a_03_1 = {75 b8 6a 00 68 ?? ?? ?? ?? 89 55 ?? 89 4d ?? ff 15 ?? ?? ?? ?? 50 ff 15 } //1
		$a_03_2 = {05 e0 33 00 00 50 56 ff 15 ?? ?? ?? ?? 5f 8d 46 01 5e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}