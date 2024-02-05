
rule VirTool_Win32_CeeInject_BED_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BED!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 45 a4 83 c4 04 8b 55 a4 8b 12 8d bd 1c fd ff ff 8b 75 a4 83 c6 04 b9 39 00 00 00 8b 1e 31 d3 89 1f 83 c6 04 83 c7 04 83 e9 01 89 c8 85 c1 75 eb 8b 45 a4 66 31 c0 66 bb 4d 5a } //01 00 
		$a_01_1 = {89 4d 90 8b 75 a8 8b 7d a8 8b 4d f8 c1 e9 02 8b 06 83 c6 04 8b 5d 90 31 d8 89 07 83 c7 04 e2 ef } //00 00 
	condition:
		any of ($a_*)
 
}