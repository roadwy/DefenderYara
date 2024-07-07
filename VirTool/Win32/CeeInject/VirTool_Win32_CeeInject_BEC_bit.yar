
rule VirTool_Win32_CeeInject_BEC_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BEC!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 1b 46 17 2c 68 90 01 04 ff 15 90 00 } //1
		$a_01_1 = {8b 55 f4 83 c2 01 89 55 f4 83 7d f4 04 73 26 8b 45 f4 33 d2 b9 04 00 00 00 f7 f1 8b 45 dc 0f be 0c 10 8b 55 f4 0f b6 44 15 e8 33 c1 8b 4d f4 88 44 0d e8 eb cb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}