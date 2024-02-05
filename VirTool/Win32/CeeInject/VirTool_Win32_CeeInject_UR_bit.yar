
rule VirTool_Win32_CeeInject_UR_bit{
	meta:
		description = "VirTool:Win32/CeeInject.UR!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 2d 8b 55 90 01 01 0f b6 8c 15 90 01 04 8b 45 90 01 01 99 be 06 00 00 00 f7 fe 0f b6 94 15 90 01 04 33 ca 51 8b 45 90 01 01 50 8d 4d ac e8 90 00 } //01 00 
		$a_03_1 = {55 8b ec 51 89 4d 90 01 01 8b 45 90 01 01 8b 08 8b 55 08 8a 45 0c 88 04 11 8b e5 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}