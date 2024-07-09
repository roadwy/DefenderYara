
rule VirTool_Win32_VBInject_OZ_bit{
	meta:
		description = "VirTool:Win32/VBInject.OZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {64 a1 30 00 00 00 [0-20] 8b 40 0c [0-20] 8b 40 14 [0-20] 8b 00 [0-20] 8b 58 28 [0-20] 81 3b 4d 00 53 00 75 [0-20] 81 7b 04 56 00 42 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule VirTool_Win32_VBInject_OZ_bit_2{
	meta:
		description = "VirTool:Win32/VBInject.OZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {64 ff 35 30 00 00 00 [0-30] 58 [0-30] 8b 40 0c [0-30] 8b 40 14 [0-30] 8b 00 [0-30] 8b 58 28 [0-30] 81 7b 04 56 00 42 00 } //1
		$a_03_1 = {83 f8 00 75 [0-30] 89 e1 [0-30] 83 c1 30 [0-30] 89 ca [0-30] 83 c2 14 [0-30] e8 [0-30] 89 e2 [0-30] 6a 00 [0-30] 8b 1a [0-30] 81 eb 00 10 00 00 [0-30] 53 [0-30] 6a 00 [0-30] 6a 00 [0-30] ff 72 68 [0-30] ff 72 6c [0-30] ff 72 70 [0-30] ff 72 74 } //2
		$a_03_2 = {3b 54 24 10 75 [0-30] b9 [0-30] 83 e9 04 [0-30] ff 34 0f [0-30] 5a [0-30] e8 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=3
 
}