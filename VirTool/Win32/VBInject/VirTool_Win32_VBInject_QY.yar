
rule VirTool_Win32_VBInject_QY{
	meta:
		description = "VirTool:Win32/VBInject.QY,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {56 b9 b8 00 00 00 89 45 ec 89 45 e8 e9 c9 ce ff ff 50 e8 85 03 00 00 8b 45 08 } //2
		$a_01_1 = {8b 0e 8d 55 dc 8d 45 e0 52 50 68 ec 41 40 00 56 ff 51 38 3b c7 7d 0f 6a 38 68 84 31 40 00 56 50 ff 15 4c 10 40 00 } //2
		$a_01_2 = {0f 80 c0 37 00 00 6a 04 50 57 89 45 dc ff 51 24 81 bd 48 fd ff ff 50 45 00 00 0f 85 4b 34 00 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}