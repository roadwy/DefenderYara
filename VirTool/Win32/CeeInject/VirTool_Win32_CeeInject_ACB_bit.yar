
rule VirTool_Win32_CeeInject_ACB_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ACB!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 40 89 45 fc 8b 45 fc 3b 45 0c 7d 1a 8b 45 08 03 45 fc 0f be 18 e8 90 01 04 33 d8 8b 45 08 03 45 fc 88 18 90 00 } //01 00 
		$a_03_1 = {d3 e8 89 45 90 01 01 83 65 90 01 01 00 81 f3 90 01 04 81 45 90 01 05 8b 45 90 01 01 23 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 5b 90 00 } //01 00 
		$a_03_2 = {eb 0d 8b 85 90 01 04 40 89 85 90 01 04 8b 85 90 01 04 3b 05 90 01 04 73 21 a1 90 01 04 03 85 90 01 04 8b 0d 90 01 04 03 8d 90 01 04 8a 89 90 01 04 88 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}