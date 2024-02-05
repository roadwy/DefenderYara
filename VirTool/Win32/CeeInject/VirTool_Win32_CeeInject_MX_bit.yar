
rule VirTool_Win32_CeeInject_MX_bit{
	meta:
		description = "VirTool:Win32/CeeInject.MX!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c0 01 89 45 90 01 01 81 7d 90 01 05 7d 16 8b 0d 90 01 04 03 4d 90 01 01 8b 55 90 01 01 8a 82 90 01 04 88 01 eb 90 00 } //01 00 
		$a_03_1 = {99 b9 03 00 00 00 f7 f9 85 d2 74 30 0f b7 15 90 01 04 81 fa 90 01 04 75 1c a1 90 01 04 03 45 90 01 01 0f be 08 81 f1 90 01 04 8b 15 90 01 04 03 55 90 01 01 88 0a 90 00 } //01 00 
		$a_03_2 = {75 1c 8b 0d 90 01 04 03 4d f4 0f be 11 81 f2 90 01 04 a1 90 01 04 03 45 f4 88 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}