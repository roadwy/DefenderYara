
rule VirTool_Win64_Komrat_A_MTB{
	meta:
		description = "VirTool:Win64/Komrat.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 8c 24 bc 00 00 00 68 cb 76 80 3b e8 90 01 04 0f b6 0d 58 27 17 10 51 8b c8 e8 90 01 04 8b 8c 24 bc 00 00 00 68 05 e0 3b 74 90 00 } //01 00 
		$a_00_1 = {8b 4d 10 51 8b 55 0c 52 68 ff ff 00 00 6a 00 8b 45 08 50 ff 15 } //01 00 
		$a_00_2 = {52 8b 45 10 50 8b 4d 0c 51 8b 55 fc 52 8b 45 08 50 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}