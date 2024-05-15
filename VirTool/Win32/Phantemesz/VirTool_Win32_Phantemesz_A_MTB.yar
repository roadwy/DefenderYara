
rule VirTool_Win32_Phantemesz_A_MTB{
	meta:
		description = "VirTool:Win32/Phantemesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d 08 51 90 01 06 52 90 02 16 83 c4 04 90 01 06 50 90 01 06 51 90 01 05 6a 00 68 04 00 00 08 6a 00 6a 00 6a 00 90 01 06 52 6a 00 90 01 06 85 c0 90 00 } //01 00 
		$a_03_1 = {55 8b ec 51 c7 45 fc 00 00 00 00 8b 45 14 50 6a 08 90 01 06 50 90 01 06 8b 4d 10 89 01 90 01 03 52 8b 45 14 50 8b 4d 10 8b 11 52 8b 45 0c 50 8b 4d 08 51 90 01 06 85 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}