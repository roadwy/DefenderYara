
rule VirTool_Win64_Calamar_A{
	meta:
		description = "VirTool:Win64/Calamar.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {55 48 89 e5 48 83 ec 40 48 89 4d 10 48 89 55 18 4c 89 45 20 44 89 4d 28 44 8b 45 28 48 8b 4d 20 48 8b 45 18 48 8d ?? ?? 48 89 54 24 20 4d 89 c1 49 89 c8 48 89 c2 48 8b 4d 10 48 8b ?? ?? ?? ?? ?? ff d0 85 c0 0f 94 c0 } //1
		$a_03_1 = {44 8b 45 20 48 8b 4d f8 48 8b 45 18 48 8d ?? ?? 48 89 54 24 20 4d 89 c1 49 89 c8 48 89 c2 48 8b 4d 10 48 8b ?? ?? ?? ?? ?? ff d0 85 c0 0f 94 c0 84 c0 } //1
		$a_03_2 = {55 48 89 e5 48 83 ec 40 48 89 4d 10 48 89 55 18 44 89 45 20 8b 45 20 48 89 c1 e8 ?? ?? ?? ?? 48 89 45 f8 48 83 7d f8 00 75 07 b8 00 00 00 00 } //1
		$a_03_3 = {48 89 85 60 09 00 00 48 8b 85 d0 08 00 00 48 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 89 54 24 20 4c 8b 95 60 09 00 00 41 b9 30 00 00 00 49 89 c8 ba 00 00 00 00 48 89 c1 ?? ?? ?? 48 8b 95 d8 03 00 00 48 8b 85 d0 08 00 00 4c 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 89 4c 24 20 41 b9 c8 02 00 00 48 89 c1 48 8b ?? ?? ?? ?? ?? ff d0 89 85 6c 09 00 00 83 bd 6c 09 00 00 00 } //1
		$a_03_4 = {41 b8 18 00 00 00 ba 00 00 00 00 48 89 c1 e8 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 89 44 24 48 48 8d ?? ?? ?? ?? ?? 48 89 44 24 40 48 8d ?? ?? ?? ?? ?? 48 89 44 24 38 48 c7 44 24 30 00 00 00 00 c7 44 24 28 14 00 00 00 c7 44 24 20 00 00 00 00 41 b9 00 00 00 00 41 b8 00 00 00 00 48 8d ?? ?? ?? ?? ?? b9 00 00 00 00 48 8b ?? ?? ?? ?? ?? ff d0 89 85 6c 09 00 00 83 bd 6c 09 00 00 00 } //1
		$a_03_5 = {48 8b 95 10 01 00 00 48 8b 85 d0 08 00 00 41 b8 ac 01 00 00 48 89 c1 e8 ?? ?? ?? ?? 48 89 85 58 09 00 00 48 8d ?? ?? 48 8d ?? ?? ?? ?? ?? b9 21 00 00 00 48 89 c7 48 89 d6 f3 48 a5 48 8b 85 58 09 00 00 48 8b 50 78 48 8b 85 d0 08 00 00 48 8d ?? ?? 41 b9 08 01 00 00 49 89 c8 48 89 c1 e8 ?? ?? ?? ?? 89 85 6c 09 00 00 83 bd 6c 09 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}