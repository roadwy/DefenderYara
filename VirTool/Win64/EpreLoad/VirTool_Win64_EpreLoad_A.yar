
rule VirTool_Win64_EpreLoad_A{
	meta:
		description = "VirTool:Win64/EpreLoad.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 38 4c 8b d1 b8 48 0f 45 d5 90 01 05 81 3f 4c 8b d1 b8 90 00 } //01 00 
		$a_03_1 = {48 8b d3 48 0f 45 d5 90 01 05 81 3e 4c 8b d1 b8 90 00 } //01 00 
		$a_01_2 = {48 0f 45 dd 48 8b d3 48 8b 5c 24 30 48 8b 6c 24 38 48 8b 74 24 40 48 83 c4 20 5f } //00 00 
	condition:
		any of ($a_*)
 
}