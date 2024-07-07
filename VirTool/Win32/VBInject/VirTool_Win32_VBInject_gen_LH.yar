
rule VirTool_Win32_VBInject_gen_LH{
	meta:
		description = "VirTool:Win32/VBInject.gen!LH,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 b9 24 00 e8 90 01 04 8b 0d 90 01 04 03 4d 90 01 01 88 01 c7 45 90 01 02 00 00 00 81 7d d4 90 01 02 00 00 73 09 83 a5 90 01 04 00 eb 0b e8 90 01 04 89 85 90 01 04 66 b9 28 00 e8 90 01 04 8b 0d 90 01 04 03 4d 90 01 01 88 01 c7 45 90 01 02 00 00 00 81 7d d4 90 01 02 00 00 73 09 83 a5 90 01 04 00 eb 0b e8 90 01 04 89 85 90 01 04 66 b9 89 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}