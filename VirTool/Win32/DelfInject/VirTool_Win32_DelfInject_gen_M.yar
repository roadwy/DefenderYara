
rule VirTool_Win32_DelfInject_gen_M{
	meta:
		description = "VirTool:Win32/DelfInject.gen!M,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 04 68 00 30 00 00 8b 45 90 01 01 8b 40 50 50 8b 45 90 01 01 8b 40 34 50 8b 45 90 01 01 50 a1 90 01 04 8b 00 ff d0 90 00 } //3
		$a_01_1 = {8b d0 83 c2 15 8d 44 24 08 88 50 01 c6 00 01 8d 54 24 08 8d 44 24 10 b1 04 e8 } //2
		$a_01_2 = {8d 34 9b 8b 45 e0 8b 44 f0 10 50 8b 45 e0 8b 44 f0 14 03 c7 50 8b 45 e0 8b 44 f0 0c 03 45 f4 } //1
		$a_03_3 = {25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 8a 84 85 90 01 02 ff ff 8b 55 90 01 01 30 04 3a 47 ff 4d 90 01 01 75 90 00 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_03_3  & 1)*2) >=5
 
}