
rule HackTool_Win64_Mimikatz_gen_G{
	meta:
		description = "HackTool:Win64/Mimikatz.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 01 00 c0 0f 84 90 01 04 81 90 01 01 4b 00 00 c0 0f 84 90 02 40 e9 90 01 01 00 00 00 81 90 01 01 4b 00 00 c0 0f 84 90 02 40 ba ff ff 00 00 90 00 } //1
		$a_03_1 = {01 00 00 c0 48 85 c9 0f 84 90 02 60 0f b7 03 83 f8 21 74 1a 83 f8 2a 74 0a 48 8b cb e8 90 01 01 00 00 00 eb 90 00 } //1
		$a_03_2 = {48 8b da 83 f9 03 75 90 02 40 45 33 c9 45 33 c0 33 d2 b9 85 04 00 00 ff 15 90 01 04 33 c0 48 83 c4 20 5b c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule HackTool_Win64_Mimikatz_gen_G_2{
	meta:
		description = "HackTool:Win64/Mimikatz.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 00 00 c0 48 85 c9 0f 84 90 02 60 48 8b d8 48 85 90 01 01 74 35 66 83 3b 21 74 1b 66 83 3b 2a 74 0a 48 8b cb e8 90 01 01 00 00 00 eb 90 00 } //1
		$a_03_1 = {48 8b da 83 f9 03 75 90 02 40 45 33 c9 45 33 c0 33 d2 b9 85 04 00 00 ff 15 90 01 04 33 c0 48 83 c4 20 5b c3 90 00 } //1
		$a_03_2 = {8b 45 33 41 bf 2c 17 5a e3 49 33 c7 48 89 03 0f 84 90 01 04 48 8d 45 77 be 08 00 00 00 44 8b c6 48 89 44 24 20 48 8b d3 48 8d 4c 24 20 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule HackTool_Win64_Mimikatz_gen_G_3{
	meta:
		description = "HackTool:Win64/Mimikatz.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 01 00 c0 0f 84 90 01 04 81 90 01 01 4b 00 00 c0 0f 84 90 02 40 e9 90 01 01 00 00 00 81 90 01 01 4b 00 00 c0 0f 84 90 02 40 ba ff ff 00 00 90 00 } //1
		$a_03_1 = {01 00 00 c0 48 85 c9 0f 84 90 02 60 48 8b d8 48 85 90 01 01 74 35 66 83 3b 21 74 1b 66 83 3b 2a 74 0a 48 8b cb e8 90 01 01 00 00 00 eb 90 00 } //1
		$a_03_2 = {48 8b da 83 f9 03 75 90 02 40 45 33 c9 45 33 c0 33 d2 b9 85 04 00 00 ff 15 90 01 04 33 c0 48 83 c4 20 5b c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}