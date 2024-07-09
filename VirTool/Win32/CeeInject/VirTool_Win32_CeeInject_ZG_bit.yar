
rule VirTool_Win32_CeeInject_ZG_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ZG!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 56 6a 00 ff 54 ?? ?? 8b 94 ?? ?? 00 00 00 a1 ?? ?? ?? ?? 52 50 ff 15 ?? ?? ?? ?? 6a 04 68 00 10 00 00 6a 04 6a 00 89 44 ?? ?? c7 44 ?? ?? ?? ?? 00 00 ff 54 } //1
		$a_03_1 = {8b c1 99 bb ?? ?? ?? 00 f7 fb 8b 44 ?? ?? 8a 1c 0f 8a 14 02 32 da 88 1c 0f 41 81 f9 ?? ?? ?? 00 7c de 0f bf 0d ?? ?? ?? 10 a1 3c a0 00 ?? 81 f1 ?? 00 00 00 3b c1 7d 0a } //2
		$a_03_2 = {8b 48 14 52 8b 50 0c 8b 44 ?? ?? 03 cf 51 03 54 ?? ?? 52 50 83 ee 28 ff d3 85 f6 7d bc } //1
		$a_03_3 = {6a 00 56 6a 00 6a 00 6a 04 6a 06 52 ff d7 8b 44 ?? ?? 50 ff ?? ?? ?? 6a 00 ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}