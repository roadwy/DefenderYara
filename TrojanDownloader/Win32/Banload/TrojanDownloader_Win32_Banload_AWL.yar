
rule TrojanDownloader_Win32_Banload_AWL{
	meta:
		description = "TrojanDownloader:Win32/Banload.AWL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {64 89 20 33 c9 b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d8 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 ba ?? ?? ?? ?? 8b c3 8b 08 ff 51 30 8d 45 fc b9 ?? ?? ?? ?? 8b 15 } //1
		$a_03_1 = {8b 45 f8 8d 55 fc e8 ?? ?? ?? ?? 8b 55 fc b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 8b 15 } //1
		$a_03_2 = {84 c0 74 73 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 05 e8 90 09 10 00 8b 15 ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule TrojanDownloader_Win32_Banload_AWL_2{
	meta:
		description = "TrojanDownloader:Win32/Banload.AWL,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 09 00 00 "
		
	strings :
		$a_02_0 = {76 61 69 6f 73 2a 00 [0-20] 2e 7a 69 70 } //2
		$a_02_1 = {6d 65 6c 68 6f 72 2a 00 [0-20] 2e 7a 69 70 } //2
		$a_02_2 = {00 31 32 33 34 35 36 37 38 39 00 [0-10] 5c [0-10] 2e 7a 69 70 } //2
		$a_02_3 = {76 61 69 6f 31 30 31 30 [0-20] 2e 7a 69 70 } //2
		$a_02_4 = {64 6f 73 38 35 36 34 37 [0-20] 2e 7a 69 70 } //2
		$a_02_5 = {5c 6c 69 62 6d 79 73 71 6c 2e 64 6c 6c 90 0a 20 00 2e (65 78 65|63 70 6c) } //2
		$a_02_6 = {5c 6c 65 74 73 6f 77 [0-05] 2e 65 78 65 00 } //2
		$a_00_7 = {43 4d 44 20 2f 43 20 53 74 61 72 74 } //1 CMD /C Start
		$a_03_8 = {64 89 20 33 c9 b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d8 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 ba ?? ?? ?? ?? 8b c3 8b 08 ff 51 30 8d 45 fc b9 ?? ?? ?? ?? 8b 15 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_02_2  & 1)*2+(#a_02_3  & 1)*2+(#a_02_4  & 1)*2+(#a_02_5  & 1)*2+(#a_02_6  & 1)*2+(#a_00_7  & 1)*1+(#a_03_8  & 1)*2) >=5
 
}