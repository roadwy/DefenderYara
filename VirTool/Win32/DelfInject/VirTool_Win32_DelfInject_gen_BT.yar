
rule VirTool_Win32_DelfInject_gen_BT{
	meta:
		description = "VirTool:Win32/DelfInject.gen!BT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 10 c1 e3 10 8b 45 fc 0f b6 04 30 c1 e0 18 03 d8 8d 46 02 33 d2 f7 75 f8 8b 45 fc } //1
		$a_03_1 = {81 3b 50 45 00 00 0f 85 90 01 02 00 00 66 8b 43 16 f6 c4 20 0f 85 90 01 02 00 00 a8 02 0f 84 90 01 02 00 00 0f b7 43 14 3d e0 00 00 00 90 00 } //1
		$a_01_2 = {c6 03 57 c6 43 01 72 c6 43 02 69 c6 43 03 74 c6 43 04 65 c6 43 05 50 c6 43 06 72 c6 43 07 6f c6 43 08 63 c6 43 09 65 c6 43 0a 73 c6 43 0b 73 c6 43 0c 4d c6 43 0d 65 c6 43 0e 6d c6 43 0f 6f c6 43 10 72 c6 43 11 79 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}