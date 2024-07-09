
rule VirTool_Win32_DelfInject_gen_AZ{
	meta:
		description = "VirTool:Win32/DelfInject.gen!AZ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {c1 e9 02 74 0e fc 8b 07 31 06 83 c6 04 83 c7 04 49 75 f3 59 83 e1 03 74 09 8a 07 30 06 46 47 49 75 f7 } //1
		$a_03_1 = {0f b6 0c 8b 8b 0c 8d ?? ?? ?? ?? 8d 70 01 81 e6 03 00 00 80 79 05 } //1
		$a_01_2 = {8d 04 b6 8b 44 c7 14 3b e8 76 02 8b e8 46 4b 75 ef } //1
		$a_03_3 = {7d 11 6a 01 8b 85 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? eb 75 6a 40 68 00 30 00 00 56 8b 45 f8 50 8b 85 ?? ?? ?? ?? 50 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}