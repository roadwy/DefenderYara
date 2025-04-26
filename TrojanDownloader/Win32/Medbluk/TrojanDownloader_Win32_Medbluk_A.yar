
rule TrojanDownloader_Win32_Medbluk_A{
	meta:
		description = "TrojanDownloader:Win32/Medbluk.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6d 65 64 69 61 2e 62 75 6c 6b 77 65 62 2e 6f 72 67 2f 73 65 61 72 63 68 2e 74 68 6e } //1 media.bulkweb.org/search.thn
		$a_00_1 = {73 70 65 61 6b 2e 63 68 65 63 6b 6e 69 6b 2e 63 6f 6d 2f 76 69 65 77 2e 74 68 6e } //1 speak.checknik.com/view.thn
		$a_00_2 = {47 45 54 20 7b 50 41 54 48 7d 20 48 54 54 50 2f 31 2e 31 0d 0a 48 6f 73 74 3a 20 7b 48 4f 53 54 7d 0d 0a 55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 3b } //1
		$a_01_3 = {8b 47 44 8b 4c 24 1c 33 c3 85 c9 74 04 8b 31 eb 02 33 f6 0f c8 33 c6 8b 74 24 20 89 06 85 c9 74 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}