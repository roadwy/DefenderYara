
rule VirTool_Win32_DelfInject_gen_CE{
	meta:
		description = "VirTool:Win32/DelfInject.gen!CE,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {7e 29 be 01 00 00 00 8d 45 f4 8b 55 fc 0f b6 54 32 ff 66 81 f2 9a 02 } //2
		$a_03_1 = {8b 40 0c 03 c3 50 90 01 1c 66 83 c0 03 8b 56 1c 03 d3 0f b7 c0 c1 e0 02 03 d0 90 00 } //1
		$a_03_2 = {6a 40 68 00 30 00 00 6a 10 6a 00 53 ff 15 90 01 04 8b f0 8d 45 f8 50 6a 10 8d 45 e4 50 56 53 ff 90 00 } //1
		$a_01_3 = {a5 a5 68 e8 03 00 00 ff 55 f8 ff 75 fc ff 55 f0 83 f8 00 74 ed 6a 00 ff 55 f4 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}