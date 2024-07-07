
rule VirTool_Win32_CobaltStrike_A{
	meta:
		description = "VirTool:Win32/CobaltStrike.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {e8 00 00 00 00 5b 52 45 55 89 e5 81 c3 90 01 04 ff d3 89 c3 57 68 04 00 00 00 50 ff d0 68 f0 b5 a2 56 68 05 00 00 00 50 ff d3 90 00 } //1
		$a_03_1 = {8e 4e 0e ec 74 90 01 01 81 7d 90 01 01 aa fc 0d 7c 74 90 01 01 81 7d 90 01 01 54 ca af 91 74 90 00 } //1
		$a_01_2 = {0f b7 40 16 25 00 80 00 00 74 09 c7 45 f0 40 00 00 00 eb 07 c7 45 f0 04 00 00 00 } //1
		$a_01_3 = {ff 75 f0 68 00 30 00 00 8b 45 f4 ff 70 50 6a 00 ff 55 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule VirTool_Win32_CobaltStrike_A_2{
	meta:
		description = "VirTool:Win32/CobaltStrike.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 06 00 00 "
		
	strings :
		$a_03_0 = {3d 00 10 00 00 90 0a 0d 00 80 b0 90 01 04 2e 40 90 00 } //5
		$a_01_1 = {89 10 89 50 04 89 48 08 89 48 0c c3 } //1
		$a_03_2 = {83 7e 08 04 73 03 33 c0 c3 8b 46 04 ff 30 e8 90 01 04 83 46 04 04 83 46 08 fc c3 90 00 } //1
		$a_03_3 = {83 7e 08 02 73 03 33 c0 c3 8b 46 04 0f b7 00 50 e8 90 01 04 83 46 04 02 83 46 08 fe 0f b7 c0 c3 90 00 } //1
		$a_01_4 = {8b 07 8b 57 04 83 c7 08 85 c0 75 2c } //5
		$a_01_5 = {8b 06 8b 56 04 83 c6 08 85 c0 75 23 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5) >=11
 
}
rule VirTool_Win32_CobaltStrike_A_3{
	meta:
		description = "VirTool:Win32/CobaltStrike.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 01 6a 02 e8 90 02 30 6a 02 58 ff 75 08 66 89 45 ec e8 90 02 40 6a 78 56 ff 15 90 00 } //1
		$a_03_1 = {8e 4e 0e ec 74 90 01 01 81 7d 90 01 01 aa fc 0d 7c 74 90 01 01 81 7d 90 01 01 54 ca af 91 74 90 00 } //1
		$a_01_2 = {0f b7 40 16 25 00 80 00 00 74 09 c7 45 f0 40 00 00 00 eb 07 c7 45 f0 04 00 00 00 } //1
		$a_01_3 = {ff 75 f0 68 00 30 00 00 8b 45 f4 ff 70 50 6a 00 ff 55 } //1
		$a_01_4 = {83 7d 9c 40 73 19 0f b6 45 a7 8b 4d 98 03 4d 9c 0f b6 09 33 c8 8b 45 98 03 45 9c 88 08 eb da } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule VirTool_Win32_CobaltStrike_A_4{
	meta:
		description = "VirTool:Win32/CobaltStrike.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {4d 5a e8 00 00 00 00 5b 89 df 52 45 55 89 e5 81 c3 90 01 02 00 00 ff d3 68 f0 b5 a2 56 68 04 00 00 00 57 ff d0 90 00 } //1
		$a_03_1 = {8e 4e 0e ec 74 90 01 01 81 7d 90 01 01 aa fc 0d 7c 74 90 01 01 81 7d 90 01 01 54 ca af 91 74 90 00 } //1
		$a_01_2 = {0f b7 40 16 25 00 80 00 00 74 09 c7 45 f0 40 00 00 00 eb 07 c7 45 f0 04 00 00 00 } //1
		$a_01_3 = {ff 75 f0 68 00 30 00 00 8b 45 f4 ff 70 50 6a 00 ff 55 } //1
		$a_01_4 = {83 7d 9c 40 73 19 0f b6 45 a7 8b 4d 98 03 4d 9c 0f b6 09 33 c8 8b 45 98 03 45 9c 88 08 eb da } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule VirTool_Win32_CobaltStrike_A_5{
	meta:
		description = "VirTool:Win32/CobaltStrike.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {e8 89 00 00 00 60 89 e5 31 d2 64 8b 52 30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 } //1
		$a_01_1 = {eb 86 5d 68 6e 65 74 00 68 77 69 6e 69 54 68 4c 77 26 07 ff d5 31 ff 57 57 57 57 57 68 3a 56 79 a7 ff d5 } //1
		$a_03_2 = {eb 86 5d 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 ff d5 b8 90 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5 50 90 02 08 50 68 ea 0f df e0 ff d5 90 00 } //1
		$a_01_3 = {eb 86 5d 31 c0 6a 40 b4 10 68 00 10 00 00 68 ff ff 07 00 6a 00 68 58 a4 53 e5 ff d5 83 c0 40 89 c7 50 31 c0 b0 70 b4 69 50 68 64 6e 73 61 54 68 4c 77 26 07 ff d5 } //1
		$a_01_4 = {68 58 a4 53 e5 ff d5 50 e9 a8 00 00 00 5a 31 c9 51 51 68 00 b0 04 00 68 00 b0 04 00 6a 01 6a 06 6a 03 52 68 45 70 df d4 ff d5 50 8b 14 24 6a 00 52 68 28 6f 7d e2 ff d5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=2
 
}