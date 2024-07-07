
rule VirTool_Win32_CeeInject_RY_bit{
	meta:
		description = "VirTool:Win32/CeeInject.RY!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 17 8d 44 10 ff 50 e8 90 01 04 5a 88 02 ff 07 4b 75 e5 90 09 07 00 8b c6 e8 90 00 } //1
		$a_03_1 = {25 ff 00 00 00 8b 15 e8 ea 46 00 33 c2 f7 d0 c3 90 09 05 00 e8 90 00 } //1
		$a_01_2 = {8b 1d b0 bb 46 00 8b 0d b4 bb 46 00 48 ff d1 33 c0 5a 59 59 64 89 10 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}