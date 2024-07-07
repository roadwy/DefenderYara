
rule VirTool_Win32_Injector_HK{
	meta:
		description = "VirTool:Win32/Injector.HK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 19 8b 45 fc 8b 4d 8c 8b 14 81 8b 45 94 03 45 fc 8b 4d 80 8a 00 88 04 11 eb d6 } //1
		$a_01_1 = {68 00 80 00 00 6a 00 8b 4d 94 51 ff 55 b0 68 00 80 00 00 6a 00 8b 55 8c 52 ff 55 b0 6a 04 68 00 10 00 00 68 00 10 03 00 6a 00 ff 55 bc 89 45 c0 } //1
		$a_01_2 = {8b 55 d8 8b 42 04 8b 4d c0 8d 94 01 00 f0 ff ff 52 ff 55 d4 83 c4 0c eb 28 } //1
		$a_01_3 = {83 c0 03 89 85 1c ff ff ff 58 8b 85 1c ff ff ff 50 ff 95 14 ff ff ff 8b 85 0c ff ff ff c9 ff e0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}