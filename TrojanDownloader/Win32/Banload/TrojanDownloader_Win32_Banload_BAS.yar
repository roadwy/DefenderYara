
rule TrojanDownloader_Win32_Banload_BAS{
	meta:
		description = "TrojanDownloader:Win32/Banload.BAS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 32 30 30 37 } //1 Start2007
		$a_01_1 = {70 77 3d 25 78 } //1 pw=%x
		$a_03_2 = {50 6a 00 6a 00 ff d3 8b d8 eb 0a 68 ?? ?? 00 00 e8 ?? ?? ?? ?? 84 db 74 f2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule TrojanDownloader_Win32_Banload_BAS_2{
	meta:
		description = "TrojanDownloader:Win32/Banload.BAS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f b6 44 30 ff 33 c3 89 45 e4 3b 7d e4 7c 0f 8b 45 e4 05 ff 00 00 00 2b c7 89 45 e4 eb 03 29 7d e4 } //2
		$a_01_1 = {34 31 41 30 32 31 41 32 32 36 41 41 32 33 41 39 41 35 32 38 37 39 39 30 45 33 36 37 46 39 35 43 46 34 35 30 34 38 } //1 41A021A226AA23A9A5287990E367F95CF45048
		$a_01_2 = {35 45 39 46 33 45 38 31 43 34 30 42 34 33 38 39 34 35 38 39 39 38 46 31 30 35 34 36 39 36 33 42 39 35 33 33 36 44 } //1 5E9F3E81C40B4389458998F10546963B95336D
		$a_03_3 = {56 4d 57 61 72 65 [0-0f] 57 69 6e 65 [0-0f] 56 69 72 74 75 61 6c 20 50 43 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}
rule TrojanDownloader_Win32_Banload_BAS_3{
	meta:
		description = "TrojanDownloader:Win32/Banload.BAS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 83 6c 03 00 00 ?? 00 00 00 8d 83 70 03 00 00 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 83 74 03 00 00 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 83 78 03 00 00 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 c0 55 } //1
		$a_01_1 = {8d 55 f7 b9 01 00 00 00 8b 45 fc 8b 38 ff 57 0c 8b ce 0f b7 45 f4 d3 e8 f6 d0 30 45 f7 8d 55 f7 b9 01 00 00 00 8b 45 f8 8b 38 ff 57 10 } //1
		$a_03_2 = {0f b6 44 30 ff 33 c3 89 45 ?? 3b 7d ?? 7c 0f 8b 45 ?? 05 ff 00 00 00 2b c7 89 45 ?? eb 03 29 7d ?? 8d 45 ?? 8b 55 ?? e8 ?? ?? ?? ?? 8b 55 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule TrojanDownloader_Win32_Banload_BAS_4{
	meta:
		description = "TrojanDownloader:Win32/Banload.BAS,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 06 00 00 "
		
	strings :
		$a_01_0 = {37 46 38 31 38 32 38 34 38 39 38 46 46 34 31 44 36 34 41 43 45 44 37 45 44 31 30 34 35 39 38 46 43 34 31 44 42 34 32 46 41 38 32 34 41 30 33 45 39 43 33 43 39 43 33 45 38 30 43 35 30 41 42 31 31 42 41 34 32 46 39 37 } //1 7F818284898FF41D64ACED7ED104598FC41DB42FA824A03E9C3C9C3E80C50AB11BA42F97
		$a_01_1 = {30 45 34 31 39 33 43 34 31 37 34 42 39 44 46 41 35 41 46 33 35 35 } //1 0E4193C4174B9DFA5AF355
		$a_01_2 = {35 38 46 31 35 37 46 41 35 41 41 35 45 35 32 34 36 37 41 36 45 37 32 37 35 31 42 38 44 37 33 38 35 44 41 34 45 33 32 37 36 46 41 46 43 44 33 45 42 30 43 30 33 35 42 35 44 35 } //1 58F157FA5AA5E52467A6E72751B8D7385DA4E3276FAFCD3EB0C035B5D5
		$a_01_3 = {38 34 44 37 30 38 35 42 38 44 43 31 31 32 37 31 44 30 30 38 34 39 } //1 84D7085B8DC11271D00849
		$a_01_4 = {8d 55 f7 b9 01 00 00 00 8b 45 fc 8b 38 ff 57 0c 8b ce 0f b7 45 f4 d3 e8 f6 d0 30 45 f7 8d 55 f7 b9 01 00 00 00 8b 45 f8 8b 38 ff 57 10 } //10
		$a_03_5 = {0f b6 44 30 ff 33 c3 89 45 ?? 3b 7d ?? 7c 0f 8b 45 ?? 05 ff 00 00 00 2b c7 89 45 ?? eb 03 29 7d ?? 8d 45 ?? 8b 55 ?? e8 ?? ?? ?? ?? 8b 55 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*10+(#a_03_5  & 1)*10) >=22
 
}