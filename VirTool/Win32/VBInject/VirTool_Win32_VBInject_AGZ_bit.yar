
rule VirTool_Win32_VBInject_AGZ_bit{
	meta:
		description = "VirTool:Win32/VBInject.AGZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 96 39 14 00 [0-10] 05 c0 c6 2d 00 [0-10] 39 41 04 75 [0-10] 68 cd 7b 34 00 [0-10] 58 [0-10] 05 80 84 1e 00 [0-10] 39 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule VirTool_Win32_VBInject_AGZ_bit_2{
	meta:
		description = "VirTool:Win32/VBInject.AGZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {64 a1 30 00 00 00 [0-10] 8b 40 0c [0-10] 8b 40 14 [0-10] 8b 40 14 [0-10] 48 66 81 38 ff 25 75 ?? e9 } //1
		$a_01_1 = {40 81 38 8b 7c 24 0c 75 f7 81 78 04 85 ff 7c 08 75 ee } //1
		$a_03_2 = {5f 81 34 1f [0-15] 66 39 d3 [0-10] 75 [0-10] ff e0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}