
rule VirTool_Win32_CeeInject_TH_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TH!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 e9 21 e3 64 98 51 b8 90 01 04 ff 10 90 00 } //01 00 
		$a_03_1 = {41 6a 00 6a 00 51 8d 05 90 01 04 ff 10 90 09 14 00 c6 05 90 01 04 67 c6 05 90 01 04 71 8d 0d 90 00 } //01 00 
		$a_03_2 = {41 6a 00 6a 00 51 8d 05 90 01 04 ff 10 90 09 0f 00 66 c7 05 90 01 03 00 6e 63 8d 0d 90 00 } //01 00 
		$a_03_3 = {5b 03 5b 3c 81 c3 a0 00 00 00 89 1d 90 01 04 8d 1d 90 01 04 81 c3 bf cd a2 89 89 1d 90 01 04 c6 05 90 01 04 4d c6 05 90 01 04 50 90 00 } //01 00 
		$a_01_4 = {31 f6 57 8b 13 f8 83 d3 04 f7 d2 f8 83 da 22 8d 52 ff 29 ca 31 c9 29 d1 f7 d9 52 8f 07 } //00 00 
	condition:
		any of ($a_*)
 
}