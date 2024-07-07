
rule HackTool_Win32_Mimikatz_gen_H{
	meta:
		description = "HackTool:Win32/Mimikatz.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {50 6a 00 68 00 01 00 00 6a 22 bb 90 01 04 53 6a 00 56 ff 15 90 01 04 8b d0 85 d2 7c 90 00 } //1
		$a_03_1 = {ba 03 c1 22 00 3b c2 0f 87 90 01 04 0f 84 90 01 04 ba 43 c0 22 00 3b c2 0f 87 90 01 04 0f 84 90 01 04 2d 03 c0 22 00 74 90 01 01 83 e8 04 74 90 00 } //1
		$a_03_2 = {53 68 69 77 69 6b ff 75 f8 6a 01 ff 15 90 01 04 8b d8 90 00 } //1
		$a_03_3 = {68 69 77 69 6b ff 75 ec ff 15 90 01 04 5b 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule HackTool_Win32_Mimikatz_gen_H_2{
	meta:
		description = "HackTool:Win32/Mimikatz.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {ff 74 24 0c 6a 00 68 10 04 00 00 ff 15 90 01 04 8b f8 85 ff 90 00 } //1
		$a_03_1 = {81 bd fc fe ff ff 4c 48 54 58 75 90 01 01 8b 45 f4 6a 10 5f 83 c0 34 eb 90 01 01 81 bd fc fe ff ff 53 48 54 58 90 00 } //1
		$a_01_2 = {c6 45 e4 ff c6 45 e5 50 c6 45 e6 10 c6 45 e7 85 c6 45 e8 c0 c6 45 e9 74 c7 45 b4 06 00 00 00 } //1
		$a_01_3 = {c6 45 e0 8b c6 45 e1 5c c6 45 e2 24 c6 45 e3 18 c6 45 e4 8b c6 45 e5 13 c7 45 d0 06 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule HackTool_Win32_Mimikatz_gen_H_3{
	meta:
		description = "HackTool:Win32/Mimikatz.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 0b 89 7d a4 ff 15 90 01 04 50 ff 15 90 01 04 85 c0 74 90 01 01 8d 45 fc 50 56 56 56 56 56 56 6a 02 ff 75 f8 ff 15 90 00 } //1
		$a_03_1 = {b9 58 1b 00 00 57 89 74 24 90 01 01 89 74 24 90 01 01 66 3b c1 73 90 01 01 bb 90 01 04 eb 90 01 01 b9 40 1f 00 00 66 3b c1 73 90 01 01 bb 90 01 04 eb 90 01 01 b9 b8 24 00 00 90 00 } //1
		$a_03_2 = {6a 04 8d 44 24 90 01 01 50 ff 74 24 90 01 01 ff 15 90 01 04 85 c0 0f 84 90 01 04 8b 44 24 90 01 01 8b 3d 90 01 04 c1 e0 03 50 6a 40 ff d7 90 00 } //1
		$a_01_3 = {6c 73 61 73 72 76 21 } //1 lsasrv!
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}