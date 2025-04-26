
rule VirTool_Win32_VBInject_AFQ{
	meta:
		description = "VirTool:Win32/VBInject.AFQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 45 a4 58 e7 0d 00 c7 45 a8 01 00 00 00 c7 45 d4 00 00 00 00 eb 0f 8b 45 d4 03 45 a8 0f 80 96 01 00 00 89 45 d4 8b 4d d4 3b 4d a4 7f 57 } //1
		$a_01_1 = {89 0c d6 c7 44 d6 04 5d f2 f3 18 8b 78 14 8b 70 0c ba 25 00 00 00 2b d7 c7 04 d6 66 0f 71 d2 c7 44 d6 04 fc 0f e2 c1 8b 70 14 ba 2f 02 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}