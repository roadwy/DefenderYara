
rule VirTool_Win32_CeeInject_UA_bit{
	meta:
		description = "VirTool:Win32/CeeInject.UA!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 35 8d 45 f8 50 6a 40 68 90 01 04 8b 45 08 50 ff 15 90 00 } //01 00 
		$a_03_1 = {8a 00 88 45 90 01 01 90 90 8b 45 90 01 01 89 45 90 01 01 80 75 90 01 01 d4 8b 45 90 01 01 03 45 90 01 01 73 05 e8 90 01 04 8a 55 90 01 01 88 10 90 00 } //01 00 
		$a_03_2 = {8b 45 08 05 4d 36 00 00 73 05 e8 90 01 04 89 45 90 01 01 ff 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}