
rule HackTool_Win64_Mimikatz_gen_H{
	meta:
		description = "HackTool:Win64/Mimikatz.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 b9 22 00 00 00 48 89 44 24 90 01 01 33 d2 48 8b cb c6 44 24 90 01 01 00 c7 44 24 90 01 01 00 01 00 00 ff 15 90 01 04 8b f8 85 c0 90 00 } //01 00 
		$a_03_1 = {ba 03 c1 22 00 3b c2 0f 87 90 01 04 0f 84 90 01 04 ba 43 c0 22 00 3b c2 0f 87 90 01 04 0f 84 90 01 04 2d 03 c0 22 00 0f 84 90 01 04 83 e8 04 90 00 } //01 00 
		$a_03_2 = {48 8b d1 41 b8 69 77 69 6b 33 c9 ff 15 90 01 04 48 89 45 00 90 00 } //01 00 
		$a_03_3 = {ba 69 77 69 6b 48 8b cf ff 15 90 01 04 8b de 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule HackTool_Win64_Mimikatz_gen_H_2{
	meta:
		description = "HackTool:Win64/Mimikatz.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {ba 0b 00 00 00 ff 15 90 01 04 85 c0 0f 84 90 01 04 48 8b 4c 24 90 01 01 48 8d 44 24 90 01 01 45 33 c9 48 89 44 24 90 01 01 48 83 64 24 90 01 01 00 83 64 24 90 01 01 00 48 83 64 24 90 01 01 00 83 64 24 90 01 01 00 41 8d 51 02 45 33 c0 ff 15 90 00 } //01 00 
		$a_03_1 = {41 b8 58 1b 00 00 66 41 3b c0 73 90 01 01 48 8d 90 01 04 90 01 01 eb 90 01 01 b9 40 1f 00 00 66 3b c1 73 90 01 01 48 8d 90 01 04 90 01 01 eb 90 01 01 b9 b8 24 00 00 90 00 } //01 00 
		$a_03_2 = {45 8d 41 04 ff 15 90 01 04 41 3b c6 0f 84 90 01 04 8b 54 24 90 01 01 bf 40 00 00 00 48 c1 e2 04 8b cf ff 15 90 00 } //01 00 
		$a_01_3 = {6c 73 61 73 72 76 21 } //00 00  lsasrv!
	condition:
		any of ($a_*)
 
}