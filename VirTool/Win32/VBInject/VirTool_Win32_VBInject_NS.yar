
rule VirTool_Win32_VBInject_NS{
	meta:
		description = "VirTool:Win32/VBInject.NS,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 45 a4 56 00 00 00 c7 45 9c 02 00 00 00 8d 75 9c 6a 00 ff 75 ac e8 90 01 04 8b c8 8b d6 e8 90 01 04 c7 45 94 57 00 00 00 c7 45 8c 02 00 00 00 8d 75 8c 6a 01 ff 75 ac e8 90 01 04 8b c8 8b d6 e8 90 01 04 c7 45 84 8b 00 00 00 90 00 } //1
		$a_03_1 = {05 f8 00 00 00 0f 80 90 01 04 8b 90 02 06 6b c9 28 90 00 } //1
		$a_00_2 = {89 45 c0 8b 45 08 8b 40 78 8b 4d dc c7 04 88 88 6a 3f 24 c7 45 fc 05 00 00 00 c7 45 dc 01 00 00 00 83 7d dc 12 73 06 83 65 bc 00 eb 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}