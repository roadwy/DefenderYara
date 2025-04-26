
rule TrojanDownloader_Win32_Renos_gen_AI{
	meta:
		description = "TrojanDownloader:Win32/Renos.gen!AI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {76 1c 8a 44 3e 01 32 04 3e 8b 4c 24 14 88 04 0b 43 46 57 46 e8 ?? ?? ?? 00 3b f0 59 72 e4 8b 44 24 14 5f 5e c6 04 03 00 5b c3 } //1
		$a_03_1 = {6a 6b 50 c7 45 d4 03 00 00 00 c7 45 d8 ?? ?? 00 10 89 7d dc 89 7d e0 89 45 e4 ff d6 68 00 7f 00 00 57 89 45 e8 ff 15 ?? ?? 00 10 6a 6c } //1
		$a_00_2 = {7b 4f 55 54 50 55 54 5f 4e 41 4d 45 7d 2e 64 6c 6c 00 69 6e 73 74 61 6c 6c 69 6e 67 00 6c 6f 61 64 69 6e 67 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}