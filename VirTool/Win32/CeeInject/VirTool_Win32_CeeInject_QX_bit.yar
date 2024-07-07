
rule VirTool_Win32_CeeInject_QX_bit{
	meta:
		description = "VirTool:Win32/CeeInject.QX!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {23 cf 8d b1 90 01 04 8a 16 0f b6 c2 03 05 90 01 04 89 0d 90 01 04 23 c7 a3 90 01 04 8d 80 90 01 04 8a 18 88 10 88 1e 0f b6 00 0f b6 f3 03 f0 81 f9 90 01 04 73 24 90 00 } //1
		$a_01_1 = {c3 30 08 c3 } //1
		$a_03_2 = {6a 6b 58 6a 65 66 a3 90 01 04 58 6a 72 66 a3 90 01 04 58 6a 6e 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}