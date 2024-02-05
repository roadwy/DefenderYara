
rule VirTool_Win64_Rapotz_A_MTB{
	meta:
		description = "VirTool:Win64/Rapotz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {48 33 c4 48 89 85 e0 01 00 00 45 33 ff 48 c7 c7 ff ff ff ff 4c 89 7c 24 40 48 8b f7 e8 } //01 00 
		$a_00_1 = {b9 08 02 00 00 48 89 45 c8 0f 11 45 a8 48 89 45 80 0f 11 45 b8 0f 11 44 24 70 e8 } //01 00 
		$a_02_2 = {48 89 7c 24 60 48 8d 90 01 03 48 8b cb f3 0f 7f 44 24 50 ff 15 90 01 04 85 c0 75 3e 90 00 } //01 00 
		$a_02_3 = {4c 89 7c 24 38 48 8d 90 01 03 48 89 44 24 30 4c 8d 90 01 02 44 89 7c 24 28 41 b9 18 00 00 00 ba ac 00 09 00 4c 89 7c 24 20 49 8b ce ff 15 90 01 04 85 c0 74 18 90 00 } //01 00 
		$a_02_4 = {48 8b 54 24 40 48 8d 90 01 05 e8 90 01 04 48 8b 4c 24 40 e8 90 01 04 48 8b f0 48 85 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}