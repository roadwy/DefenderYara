
rule VirTool_Win32_VBInject_AET{
	meta:
		description = "VirTool:Win32/VBInject.AET,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 45 a0 58 e7 0d 00 c7 45 a4 01 00 00 00 c7 45 d0 00 00 00 00 eb 0f 8b 45 d0 03 45 a4 0f 80 d6 0f 00 00 89 45 d0 8b 4d d0 3b 4d a0 0f 8f cc 0d 00 00 } //1
		$a_01_1 = {c7 04 ca d3 dd d1 79 c7 44 ca 04 4a 25 d4 78 8b 50 14 b9 3f 02 00 00 2b ca 8b 50 0c c7 04 ca f7 43 66 0f c7 44 ca 04 fd c4 66 0f 8b 58 14 8b 50 0c b9 e5 01 00 00 2b cb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}