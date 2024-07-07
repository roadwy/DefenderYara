
rule VirTool_Win32_VBInject_AEV{
	meta:
		description = "VirTool:Win32/VBInject.AEV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {bf 74 23 11 00 c7 43 34 04 00 00 00 39 7b 34 0f 8f 1f 01 00 00 51 51 d9 e8 dd 1c 24 e8 d2 a1 fe ff dd d8 } //1
		$a_01_1 = {c7 81 98 09 00 00 2d 51 a4 3b 8b 48 54 c7 81 68 13 00 00 f1 b9 66 0f 8b 48 54 c7 81 dc 13 00 00 74 c7 0f d8 8b 48 54 c7 81 98 11 00 00 d6 ae a4 c7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule VirTool_Win32_VBInject_AEV_2{
	meta:
		description = "VirTool:Win32/VBInject.AEV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {73 00 61 00 6b 00 6c 00 63 00 73 00 6e 00 61 00 6b 00 6a 00 63 00 6e 00 73 00 61 00 6c 00 6b 00 6d 00 6b 00 6c 00 33 00 32 00 34 00 66 00 73 00 } //1 saklcsnakjcnsalkmkl324fs
		$a_03_1 = {64 a1 30 00 8b 90 01 02 c7 90 01 02 00 00 8b 40 8b 90 01 02 c7 90 01 02 10 8b 70 3c 8b 90 01 02 c7 90 01 02 0f b7 48 38 8b 90 01 02 c7 90 01 02 8b 7c 24 04 8b 90 01 02 c7 90 01 02 51 fc f3 a4 8b 90 01 02 c7 90 01 02 59 8b 74 24 8b 90 01 02 c7 90 01 02 04 89 4e fc 8b 90 01 02 c7 90 01 02 c3 00 00 00 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}