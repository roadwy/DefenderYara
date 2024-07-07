
rule VirTool_Win32_VBInject_ADX{
	meta:
		description = "VirTool:Win32/VBInject.ADX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_00_0 = {48 3d 45 02 00 00 89 45 e0 0f 8c 95 14 00 00 6a 02 5f 33 f6 } //2
		$a_03_1 = {8b 52 10 d1 f8 88 0c 02 8d 45 a8 50 8d 45 a8 50 8d 45 b8 50 8d 45 c8 50 6a 04 e8 90 01 02 fa ff 83 c4 14 6a 02 58 03 f0 8b 45 e0 e9 65 ff ff ff 90 00 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}