
rule TrojanDropper_Win32_Cutwail_gen_K{
	meta:
		description = "TrojanDropper:Win32/Cutwail.gen!K,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 f6 66 be c5 ee 66 81 ee b6 ee 2b f1 2b fe eb 90 01 01 33 c0 66 8b 07 c1 e0 02 8b 73 1c 03 f2 03 f0 ad 03 c2 90 00 } //1
		$a_00_1 = {8b 7d 08 8a 45 0c 8a e0 66 50 c1 e0 10 66 58 8b 4d 10 c1 e9 02 fc f2 ab 8b 4d 10 83 e1 03 f2 aa } //1
		$a_03_2 = {8b 45 f0 33 d2 b9 3d 00 00 00 f7 f1 8b 45 08 03 45 f8 8a 8a 90 01 04 88 08 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule TrojanDropper_Win32_Cutwail_gen_K_2{
	meta:
		description = "TrojanDropper:Win32/Cutwail.gen!K!!Cutwail.gen!K,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 f6 66 be c5 ee 66 81 ee b6 ee 2b f1 2b fe eb 90 01 01 33 c0 66 8b 07 c1 e0 02 8b 73 1c 03 f2 03 f0 ad 03 c2 90 00 } //1
		$a_00_1 = {8b 7d 08 8a 45 0c 8a e0 66 50 c1 e0 10 66 58 8b 4d 10 c1 e9 02 fc f2 ab 8b 4d 10 83 e1 03 f2 aa } //1
		$a_03_2 = {8b 45 f0 33 d2 b9 3d 00 00 00 f7 f1 8b 45 08 03 45 f8 8a 8a 90 01 04 88 08 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}