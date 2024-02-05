
rule VirTool_Win32_CeeInject_BCF_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BCF!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 0b 81 f9 43 54 53 0a 75 06 2b 43 04 83 e8 18 } //01 00 
		$a_01_1 = {d1 e8 35 20 83 b8 ed eb 02 } //01 00 
		$a_01_2 = {0f b6 04 39 33 c6 25 ff 00 00 00 c1 ee 08 33 b4 85 00 fc ff ff 41 3b ca 72 e6 } //00 00 
	condition:
		any of ($a_*)
 
}