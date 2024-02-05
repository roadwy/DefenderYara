
rule VirTool_Win32_CeeInject_SH_bit{
	meta:
		description = "VirTool:Win32/CeeInject.SH!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {52 6a 00 56 50 6a 00 6a 00 53 a1 90 01 04 8b 00 ff d0 8b f8 80 7d 08 00 74 90 00 } //01 00 
		$a_03_1 = {89 3b 83 c3 90 01 01 8b d7 2b 55 90 01 01 0f af 55 90 01 01 8b 45 90 01 01 0f af 45 90 01 01 03 c3 33 c9 90 00 } //01 00 
		$a_03_2 = {8b c3 83 c0 90 01 01 8b d7 0f af 55 90 01 01 03 c2 8b 4d 90 01 01 2b cf 8b d6 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}