
rule VirTool_Win64_Alanzoh_A{
	meta:
		description = "VirTool:Win64/Alanzoh.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_03_0 = {53 57 56 83 ec 08 8b 0d 34 50 ?? ?? 8b 44 24 18 31 e1 89 4c 24 04 c7 04 24 00 00 00 00 50 6a 00 6a 2a ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 8b 5c 24 1c 89 c6 6a 40 68 00 30 00 00 53 6a 00 50 ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 89 c7 89 e0 50 53 ff 74 24 28 57 56 ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 6a 00 6a 00 6a 00 57 6a 00 6a 00 56 ff 15 ?? ?? ?? ?? 85 c0 } //1
		$a_03_1 = {55 89 e5 53 83 e4 f0 83 ec 30 a1 34 50 ?? ?? 0f 57 c0 31 e8 89 44 24 20 c7 44 24 0c 00 00 00 00 0f 29 44 24 10 ff 15 ?? ?? ?? ?? 8d 4c ?? ?? 51 6a 28 50 ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 8d 44 ?? ?? 50 68 86 01 ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 85 c0 ?? ?? c7 44 24 10 01 00 00 00 c7 44 24 1c 02 00 00 00 8d 44 ?? ?? 6a 00 6a 00 6a 10 50 6a 00 ff 74 24 20 ff 15 } //1
		$a_03_2 = {8b 1b 85 db ?? ?? 8d 74 ?? ?? c7 44 24 70 00 00 00 00 56 6a 00 ff 15 ?? ?? ?? ?? 8b 5c 24 14 83 f8 6f 0f ?? ?? ?? ?? ?? 6a 01 ff 74 24 74 e8 ?? ?? ?? ?? 83 c4 08 85 c0 0f ?? ?? ?? ?? ?? 56 50 89 44 24 18 ff 15 ?? ?? ?? ?? 85 c0 } //1
		$a_03_3 = {89 c7 50 68 eb ff ?? ?? 53 e8 ?? ?? ?? ?? 85 c0 0f ?? ?? ?? ?? ?? 8b 74 24 70 83 7c 24 68 00 0f ?? ?? ?? ?? ?? 31 c0 89 7c 24 18 } //1
		$a_03_4 = {55 89 e5 53 57 56 83 e4 f0 b8 b0 41 00 00 e8 ?? ?? ?? ?? a1 34 50 ?? ?? 8d 74 ?? ?? 0f 57 c0 8d 4c ?? ?? 31 e8 89 84 24 a8 41 00 00 c7 44 24 24 0c 00 00 00 c7 44 24 2c 01 00 00 00 0f 29 44 24 70 0f 29 44 24 60 0f 29 44 24 50 0f 29 44 24 40 c7 84 24 84 00 00 00 00 00 00 00 c7 84 24 80 00 00 00 00 00 00 00 0f 29 44 24 30 c7 44 24 20 00 00 00 00 c7 44 24 1c 00 00 00 00 c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 c7 44 24 28 00 00 00 00 c7 44 24 10 00 00 00 00 8d 44 24 14 6a 00 56 50 51 ff 15 } //1
		$a_03_5 = {8b 8c bc a8 01 00 00 85 c9 ?? ?? c7 84 24 98 00 00 00 00 00 00 00 c7 84 24 94 00 00 00 00 00 00 00 51 6a 00 68 d0 04 00 00 ff 15 ?? ?? ?? ?? 85 c0 89 84 24 9c 00 00 00 ?? ?? 68 04 01 00 00 6a 00 8d 9c ?? ?? ?? ?? ?? 53 89 c6 e8 ?? ?? ?? ?? 83 c4 0c 68 04 01 00 00 53 89 74 24 10 56 e8 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 8b 44 24 0c ff 70 10 53 e8 ?? ?? ?? ?? 83 c4 08 85 c0 0f 84 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8d 8c ?? ?? ?? ?? ?? 51 50 ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 8d 84 ?? ?? ?? ?? ?? 50 ff b4 bc ac 01 00 00 ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 8b 84 24 94 00 00 00 3b 84 24 98 00 00 00 0f 85 ?? ?? ?? ?? 8b 7c 24 14 c7 84 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=5
 
}