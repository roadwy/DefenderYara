
rule VirTool_Win32_CeeInject_QJ_bit{
	meta:
		description = "VirTool:Win32/CeeInject.QJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8d 45 e4 0f 43 45 e4 c6 40 ?? ?? 50 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 58 } //2
		$a_03_1 = {89 37 8b 06 8b 40 ?? 8b 4c 30 ?? 85 c9 74 05 8b 01 ff 50 04 } //1
		$a_01_2 = {72 28 2b 3e 33 c9 c1 ff 02 42 8b c7 d1 e8 2b d8 03 c7 3b df 0f 43 c8 3b ca 0f 43 d1 8b ce 52 e8 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}