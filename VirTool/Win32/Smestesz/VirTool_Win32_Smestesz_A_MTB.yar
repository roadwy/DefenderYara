
rule VirTool_Win32_Smestesz_A_MTB{
	meta:
		description = "VirTool:Win32/Smestesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 44 24 0c 40 00 00 00 c7 44 24 08 00 30 00 00 c7 44 24 04 cc 01 00 00 c7 04 24 00 00 00 00 90 01 05 83 ec 10 89 45 e4 c7 04 24 94 50 40 00 90 01 05 8b 45 e4 bb 20 70 40 00 ba cc 01 00 00 8b 0b 89 08 8b 4c 13 fc 89 4c 10 fc 90 01 03 83 e7 fc 90 00 } //01 00 
		$a_03_1 = {55 89 e5 83 ec 38 c7 44 24 18 00 00 00 00 c7 44 24 14 80 00 00 00 c7 44 24 10 04 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 01 00 00 00 c7 44 24 04 00 00 00 80 8b 45 08 89 04 24 90 01 05 83 ec 1c 89 45 f4 83 7d f4 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}