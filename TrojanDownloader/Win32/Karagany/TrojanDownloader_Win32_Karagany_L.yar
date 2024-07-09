
rule TrojanDownloader_Win32_Karagany_L{
	meta:
		description = "TrojanDownloader:Win32/Karagany.L,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3c 3e 2e 2d 61 62 63 64 65 66 67 76 77 69 6f 6e 6c 6d 6b 68 74 70 } //1 <>.-abcdefgvwionlmkhtp
		$a_01_1 = {ff 45 f8 8b 4d f8 8a 09 84 c9 75 d3 83 65 f8 00 8b ce eb 13 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_Win32_Karagany_L_2{
	meta:
		description = "TrojanDownloader:Win32/Karagany.L,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 04 8d 8e ac 04 00 00 51 6a 02 50 ff d7 6a 04 8d 86 b4 04 00 00 50 6a 06 ff b6 08 04 00 00 ff d7 6a 04 } //1
		$a_03_1 = {89 48 08 c7 45 ?? b9 7b 59 42 c7 45 ?? 92 42 63 d5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}