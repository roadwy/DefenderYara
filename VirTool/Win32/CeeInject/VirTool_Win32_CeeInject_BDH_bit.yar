
rule VirTool_Win32_CeeInject_BDH_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BDH!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 89 45 fc 8b 5d fc 90 02 10 81 c3 90 02 10 ff d3 90 00 } //1
		$a_03_1 = {8d 45 f8 50 6a 40 68 90 01 04 56 e8 90 01 03 ff 90 02 10 33 c0 89 45 fc 90 00 } //1
		$a_03_2 = {ff 45 f8 43 90 0a f0 00 8a 03 90 02 10 34 90 01 01 90 02 10 92 e8 90 01 03 ff 90 02 10 8b 4d fc 90 02 10 83 c1 01 90 02 10 89 4d fc 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}