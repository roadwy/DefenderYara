
rule VirTool_Win64_Privilosz_A_MTB{
	meta:
		description = "VirTool:Win64/Privilosz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 c7 44 24 40 30 01 00 00 8d 90 01 02 ff 15 90 01 04 48 90 01 04 bf ff ff ff ff 48 8b c8 48 8b d8 ff 15 90 01 04 85 c0 74 5e 48 90 01 04 48 8b cb ff 15 90 01 04 85 c0 74 90 00 } //01 00 
		$a_03_1 = {48 8b d8 48 85 c0 0f 84 49 01 00 00 48 8d 90 01 05 e8 90 01 04 48 8b c8 48 85 c0 0f 84 31 01 00 00 0f 57 c0 48 89 5d 58 33 c0 48 c7 45 38 12 12 12 12 48 89 90 00 } //01 00 
		$a_03_2 = {8b d6 48 8d 90 01 05 e8 90 01 04 48 8d 90 01 05 4c 89 7c 24 68 48 90 01 03 ff 15 90 01 04 48 90 01 03 c7 45 a0 30 00 00 00 0f 57 c0 48 89 90 00 } //01 00 
		$a_03_3 = {48 8b 5c 24 68 48 8d 90 01 05 48 8b c3 48 8b fb 8b d0 e8 90 01 04 b9 00 01 00 00 ff 15 90 01 04 4c 8b f8 48 8b ce 33 c0 48 89 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}