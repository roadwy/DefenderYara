
rule VirTool_Win64_Shelljec_A_MTB{
	meta:
		description = "VirTool:Win64/Shelljec.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {48 8b c8 48 8d 90 01 05 ff 15 90 01 04 44 8b c3 33 d2 b9 ff ff 1f 00 ff 90 00 } //01 00 
		$a_02_1 = {c7 44 24 20 40 00 00 00 41 b9 00 30 00 00 41 b8 c8 00 00 00 48 8b cf ff 15 90 01 04 48 8b d8 48 85 c0 90 00 } //01 00 
		$a_02_2 = {48 89 74 24 50 4c 8d 90 01 05 33 f6 41 b9 c8 00 00 00 48 8b d3 48 89 74 24 20 48 8b cf ff 90 00 } //01 00 
		$a_00_3 = {48 89 74 24 30 4c 8b cb 89 74 24 28 45 33 c0 33 d2 48 89 74 24 20 48 8b cf ff } //01 00 
		$a_02_4 = {ba ff ff ff ff 48 8b ce ff 15 90 01 04 48 8b 0d a3 29 00 00 48 8d 90 01 05 e8 90 01 04 48 8b c8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}