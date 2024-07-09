
rule TrojanDownloader_Win32_Banload_gen_F{
	meta:
		description = "TrojanDownloader:Win32/Banload.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 05 00 00 "
		
	strings :
		$a_00_0 = {ff ff ff ff 13 00 00 00 41 72 71 75 69 76 6f 20 63 6f 72 72 6f 6d 70 69 64 6f 2e 00 ff ff ff ff 1e 00 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 69 6d 67 6c 6f 67 2e 65 78 65 } //10
		$a_02_1 = {68 74 74 70 3a 2f 2f [0-40] 2f [0-16] 2e (65 78 65|6a 70 67) } //10
		$a_00_2 = {64 ff 30 64 89 20 6a 00 6a 00 8b 45 f8 e8 e1 e8 f9 ff 50 8b 45 fc e8 d8 e8 f9 ff 50 6a 00 e8 9c 0b fc ff 85 c0 0f 94 c3 33 c0 5a 59 59 64 89 10 } //10
		$a_00_3 = {41 64 6f 62 65 20 46 6c 61 73 68 20 50 6c 61 79 65 72 } //1 Adobe Flash Player
		$a_00_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=32
 
}