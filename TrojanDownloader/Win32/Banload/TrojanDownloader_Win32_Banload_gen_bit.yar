
rule TrojanDownloader_Win32_Banload_gen_bit{
	meta:
		description = "TrojanDownloader:Win32/Banload.gen!bit,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 4c 6f 63 61 6c 65 73 } //10 Software\Borland\Delphi\Locales
		$a_03_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 [0-10] 75 72 6c 6d 6f 6e 2e 64 6c 6c [0-30] 41 50 50 44 41 54 41 } //1
		$a_03_2 = {00 70 68 70 00 [0-40] 00 6e 6f 74 69 66 79 00 [0-40] 00 3a 2f 2f 00 [0-49] 00 7a 69 70 00 } //1
		$a_01_3 = {5c 6c 6f 67 2e 74 78 74 } //1 \log.txt
		$a_03_4 = {53 8b d8 8b d3 b8 ?? ?? ?? 00 e8 ?? ?? ?? ff 5b c3 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=14
 
}
rule TrojanDownloader_Win32_Banload_gen_bit_2{
	meta:
		description = "TrojanDownloader:Win32/Banload.gen!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8d 55 fc b8 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 55 fc 8d 83 ?? ?? ?? ?? e8 ?? ?? ?? ff e8 ?? ?? ?? ff 8d 55 f8 b8 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 55 f8 8d 83 ?? ?? ?? ?? e8 ?? ?? ?? ff 68 ?? ?? ?? ?? e8 ?? ?? ?? ff e8 ?? ?? ?? ff 8d 55 e8 b8 ?? ?? ?? 00 e8 ?? ?? ?? ff } //1
		$a_03_1 = {8b 45 f8 8b 55 ?? 8a 44 10 ff 3a 45 ?? 74 1b 3a 07 74 17 25 ff 00 00 00 8a 80 ?? ?? ?? 00 33 d2 8a 17 3a 82 ?? ?? ?? 00 75 0d ff 4d ?? 4f 3b 75 ?? 7e cd } //1
		$a_03_2 = {00 41 50 50 44 41 54 41 00 [0-30] 5c 6c 6f 67 2e 74 78 74 } //1
		$a_03_3 = {5f 63 6f 6d [0-40] 5f 62 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}