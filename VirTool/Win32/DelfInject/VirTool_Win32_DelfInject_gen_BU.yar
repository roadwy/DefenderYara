
rule VirTool_Win32_DelfInject_gen_BU{
	meta:
		description = "VirTool:Win32/DelfInject.gen!BU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f 01 4d f5 8a 45 fa 3c e8 74 04 3c ff } //1
		$a_03_1 = {6a 04 8d 45 f0 50 53 e8 90 01 04 8d 45 f4 8b 55 f0 e8 90 01 04 6a 00 6a 00 68 05 04 00 00 53 e8 90 00 } //1
		$a_03_2 = {8d 34 9b 8b 45 90 01 01 8b 44 f0 10 50 8b 45 90 01 01 8b 44 f0 14 03 45 90 01 01 50 8b 45 90 01 01 8b 44 f0 0c 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}