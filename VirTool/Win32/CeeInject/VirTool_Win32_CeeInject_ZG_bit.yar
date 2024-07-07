
rule VirTool_Win32_CeeInject_ZG_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ZG!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 56 6a 00 ff 54 90 01 02 8b 94 90 01 02 00 00 00 a1 90 01 04 52 50 ff 15 90 01 04 6a 04 68 00 10 00 00 6a 04 6a 00 89 44 90 01 02 c7 44 90 01 04 00 00 ff 54 90 00 } //1
		$a_03_1 = {8b c1 99 bb 90 01 03 00 f7 fb 8b 44 90 01 02 8a 1c 0f 8a 14 02 32 da 88 1c 0f 41 81 f9 90 01 03 00 7c de 0f bf 0d 90 01 03 10 a1 3c a0 00 90 01 01 81 f1 90 01 01 00 00 00 3b c1 7d 0a 90 00 } //2
		$a_03_2 = {8b 48 14 52 8b 50 0c 8b 44 90 01 02 03 cf 51 03 54 90 01 02 52 50 83 ee 28 ff d3 85 f6 7d bc 90 00 } //1
		$a_03_3 = {6a 00 56 6a 00 6a 00 6a 04 6a 06 52 ff d7 8b 44 90 01 02 50 ff 90 01 03 6a 00 ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}