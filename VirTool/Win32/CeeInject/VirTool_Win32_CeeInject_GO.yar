
rule VirTool_Win32_CeeInject_GO{
	meta:
		description = "VirTool:Win32/CeeInject.GO,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 45 fc ff 35 ?? ?? ?? ?? ff 75 fc e8 ?? ?? ?? ?? 89 45 f0 ff 75 f8 ff 75 f4 ff 35 ?? ?? ?? ?? 6a 00 ff 55 f0 89 45 fc 68 ?? ?? ?? ?? 68 ?? ?? 00 00 68 ?? ?? ?? ?? ff 75 fc e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 75 fc c3 90 09 0a 00 68 ?? ?? ?? ?? e8 } //3
		$a_03_1 = {0f 9f c1 d3 f8 90 09 0b 00 8b ?? 33 ?? ?? ?? 33 c9 83 } //1
		$a_03_2 = {0f 9d c1 2b c1 90 0a 0c 00 33 ?? [0-02] 83 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}
rule VirTool_Win32_CeeInject_GO_2{
	meta:
		description = "VirTool:Win32/CeeInject.GO,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {b1 71 f6 e9 8a c8 8a c3 02 05 ?? ?? 00 10 80 c2 4b 80 3d c2 ?? ?? 10 21 88 0d c1 ?? ?? 10 88 15 ?? ?? 00 10 a2 c7 ?? ?? 10 c6 05 ?? ?? 00 10 7c 7c 1a } //1
		$a_03_1 = {68 45 42 0f 00 6a 00 ff d7 8b 95 ?? ?? ff ff 6a 00 8d 8d ?? ?? ff ff 51 8b d8 0f b6 05 ?? ?? ?? 10 68 46 42 0f 00 56 04 71 } //1
		$a_01_2 = {83 fe 39 0f 95 c0 0b c3 33 c9 83 fa 3c 0f 94 c1 c1 e6 64 03 c1 85 f6 74 07 } //1
		$a_03_3 = {69 c9 9c 37 00 00 03 ca 8d 54 ?? ?? 52 6a 40 89 0d ?? ?? ?? 00 8b 0d ?? ?? ?? 00 68 04 30 00 00 51 c7 44 ?? ?? 40 00 00 00 ff d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=1
 
}