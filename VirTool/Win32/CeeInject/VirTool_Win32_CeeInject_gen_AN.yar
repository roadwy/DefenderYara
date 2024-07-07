
rule VirTool_Win32_CeeInject_gen_AN{
	meta:
		description = "VirTool:Win32/CeeInject.gen!AN,SIGNATURE_TYPE_PEHSTR_EXT,09 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 ff 77 50 ff 77 34 ff 74 24 34 ff 15 } //2
		$a_01_1 = {b8 68 58 4d 56 } //1
		$a_03_2 = {0f b7 47 06 ff 44 24 90 01 01 83 44 24 20 28 39 44 24 90 01 01 7d 90 00 } //1
		$a_03_3 = {b9 e8 03 00 00 0f b6 04 07 03 45 90 01 01 f7 f1 8b 45 90 01 01 0f b6 1c 06 33 c0 2b da 39 05 90 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}