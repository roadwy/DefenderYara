
rule VirTool_Win64_CobaltStrike_A{
	meta:
		description = "VirTool:Win64/CobaltStrike.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 8b 10 41 8b 40 04 4d 8d 40 08 85 d2 75 04 } //2
		$a_01_1 = {45 8b 0a 41 8b 42 04 4d 8d 52 08 45 85 c9 } //2
		$a_01_2 = {2b c1 4c 8b c1 44 8b c8 48 8b 0b 8a 43 10 42 30 04 01 49 ff c0 49 ff c9 75 ee } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}
rule VirTool_Win64_CobaltStrike_A_2{
	meta:
		description = "VirTool:Win64/CobaltStrike.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f0 e8 c8 00 00 00 41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a } //1
		$a_01_1 = {e9 4f ff ff ff 5d 6a 00 49 be 77 69 6e 69 6e 65 74 00 41 56 49 89 e6 4c 89 f1 41 ba 4c 77 26 07 ff d5 48 31 c9 48 31 d2 4d 31 c0 4d 31 c9 41 50 41 50 41 ba 3a 56 79 a7 ff d5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule VirTool_Win64_CobaltStrike_A_3{
	meta:
		description = "VirTool:Win64/CobaltStrike.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {81 f9 8e 4e 0e ec 74 90 01 01 81 f9 aa fc 0d 7c 74 90 01 01 81 f9 54 ca af 91 74 90 00 } //1
		$a_01_1 = {0f b7 45 16 66 23 c1 66 f7 d8 b8 00 40 00 00 45 1b e4 41 83 e4 3c 41 83 c4 04 44 89 64 24 20 66 85 45 16 } //1
		$a_01_2 = {ff d6 45 33 db 48 85 db 75 21 8b 55 50 45 8b cc 33 c9 41 b8 00 30 00 00 41 ff d5 } //1
		$a_01_3 = {b9 40 00 00 00 48 03 f3 48 8b c5 f3 a4 b9 40 00 00 00 44 30 00 49 03 c5 49 2b cd } //1
		$a_01_4 = {48 b8 73 79 73 74 65 6d 33 32 48 83 cb ff 48 89 07 4c 8b c3 49 ff c0 42 80 7c 07 09 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule VirTool_Win64_CobaltStrike_A_4{
	meta:
		description = "VirTool:Win64/CobaltStrike.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {4d 5a 41 52 55 48 89 e5 48 81 ec 20 00 00 00 48 8d 1d ea ff ff ff 48 89 df 48 81 c3 90 01 04 ff d3 41 b8 f0 b5 a2 56 68 04 00 00 00 5a 48 89 f9 ff d0 90 00 } //1
		$a_03_1 = {81 f9 8e 4e 0e ec 74 90 01 01 81 f9 aa fc 0d 7c 74 90 01 01 81 f9 54 ca af 91 74 90 00 } //1
		$a_01_2 = {0f b7 45 16 66 23 c1 66 f7 d8 b8 00 40 00 00 45 1b e4 41 83 e4 3c 41 83 c4 04 44 89 64 24 20 66 85 45 16 } //1
		$a_01_3 = {ff d6 45 33 db 48 85 db 75 21 8b 55 50 45 8b cc 33 c9 41 b8 00 30 00 00 41 ff d5 } //1
		$a_01_4 = {b9 40 00 00 00 48 03 f3 48 8b c5 f3 a4 b9 40 00 00 00 44 30 00 49 03 c5 49 2b cd } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}