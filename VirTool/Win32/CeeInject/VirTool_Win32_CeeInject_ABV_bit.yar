
rule VirTool_Win32_CeeInject_ABV_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ABV!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 45 fc 83 65 f4 00 a3 90 01 04 81 f3 90 01 04 81 6d f4 90 01 04 81 45 f4 90 01 04 8b 4d f4 d3 e8 5b 25 ff 7f 00 00 90 00 } //1
		$a_03_1 = {83 c4 0c 5f 5e a1 90 01 04 a3 90 01 04 ff d0 90 09 16 00 68 90 01 04 ff 35 90 01 04 ff 35 90 01 04 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}