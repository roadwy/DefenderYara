
rule VirTool_Win32_Conjecture_A_MTB{
	meta:
		description = "VirTool:Win32/Conjecture.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 85 64 ff ff ff c7 85 54 ff ff ff 00 00 00 00 8b 8d 54 ff ff ff 51 8b 15 28 b6 41 00 52 8b 45 84 50 8b 8d 64 ff ff ff 51 8b 95 44 ff ff ff 52 ff 15 90 01 04 89 45 8c 83 7d 8c 00 90 01 02 ff 15 90 01 04 50 68 18 a3 41 00 e8 90 01 04 83 c4 08 90 00 } //01 00 
		$a_03_1 = {68 3c a3 41 00 e8 90 01 04 83 c4 04 6a 00 8b 85 48 ff ff ff 50 8b 8d 64 ff ff ff 51 ff 15 90 01 04 8b 95 48 ff ff ff 52 ff 15 90 01 04 8b 85 48 ff ff ff 50 90 00 } //01 00 
		$a_03_2 = {8b 45 0c 8b 0c 10 51 68 6c a2 41 00 e8 90 01 04 83 c4 08 ba 04 00 00 00 6b c2 03 8b 4d 0c 8b 14 01 52 e8 90 01 04 83 c4 04 83 c0 01 90 00 } //01 00 
		$a_03_3 = {8b 45 0c 8b 0c 10 51 ba 04 00 00 00 c1 e2 02 8b 45 0c 8b 0c 10 51 ff 15 90 01 04 89 45 8c 83 7d 8c 00 90 01 02 ff 15 90 01 04 50 68 c8 a2 41 00 e8 90 01 04 83 c4 08 ba 04 00 00 00 c1 e2 02 8b 45 0c 8b 0c 10 51 68 e8 a2 41 00 e8 90 01 04 83 c4 08 6a 40 68 00 30 00 00 8b 15 28 b6 41 00 52 6a 00 8b 85 44 ff ff ff 50 ff 15 90 01 04 89 85 64 ff ff ff c7 85 54 ff ff ff 00 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}