
rule VirTool_Win32_Alanzoh_D{
	meta:
		description = "VirTool:Win32/Alanzoh.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 13 8b 6b 04 0f b6 14 2a 8b 6b 0c 30 54 0d 00 8b 53 04 8b 4b 10 83 c2 01 89 53 04 83 c1 01 89 4b 10 3b 53 08 } //01 00 
		$a_02_1 = {c7 44 24 48 0c 00 00 00 c7 44 24 50 01 00 00 00 c7 44 24 4c 00 00 00 00 c7 44 24 44 00 00 00 00 c7 44 24 40 00 00 00 00 8d 90 01 03 8d 90 01 03 8d 90 01 03 6a 00 51 50 56 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}