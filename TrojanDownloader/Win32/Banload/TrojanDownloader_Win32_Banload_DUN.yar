
rule TrojanDownloader_Win32_Banload_DUN{
	meta:
		description = "TrojanDownloader:Win32/Banload.DUN,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_00_0 = {6e 65 74 20 73 74 6f 70 20 53 68 61 72 65 64 41 63 63 65 73 73 } //1 net stop SharedAccess
		$a_00_1 = {2e 74 78 74 } //1 .txt
		$a_00_2 = {2a 2e 6d 62 6f 78 } //1 *.mbox
		$a_00_3 = {2a 2e 77 61 62 } //1 *.wab
		$a_00_4 = {2a 2e 6d 62 78 } //1 *.mbx
		$a_00_5 = {2a 2e 65 6d 6c } //1 *.eml
		$a_00_6 = {2a 2e 74 62 62 } //1 *.tbb
		$a_00_7 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_02_8 = {33 ff 8d 45 e0 50 b9 02 00 00 00 ba 01 00 00 00 8b 45 fc e8 ?? ?? fe ff 8b 4d e0 8d 45 e4 ba ?? ?? 41 00 e8 ?? ?? fe ff 8b 45 e4 e8 ?? ?? fe ff 89 45 f0 be 03 00 00 00 8d 45 d8 50 b9 02 00 00 00 8b d6 8b 45 fc } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_02_8  & 1)*1) >=9
 
}
rule TrojanDownloader_Win32_Banload_DUN_2{
	meta:
		description = "TrojanDownloader:Win32/Banload.DUN,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 63 72 73 73 2e 65 78 65 00 } //1
		$a_00_1 = {2f 73 79 73 2e 65 78 65 00 } //1
		$a_00_2 = {2f 64 6f 73 2e 65 78 65 00 } //1
		$a_02_3 = {64 ff 30 64 89 20 33 d2 b8 ?? ?? ?? ?? e8 ?? ?? ff ff 8d 45 e8 e8 ?? ?? ff ff ff 75 e8 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 ec ba 03 00 00 00 e8 ?? ?? ff ff 8b 55 ec b8 ?? ?? ?? ?? e8 ?? ?? ff ff 84 c0 74 2c 8d 45 e0 e8 ?? ?? ff ff ff 75 e0 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 e4 ba 03 00 00 00 e8 ?? ?? ff ff 8b 45 e4 33 d2 e8 ?? ?? ff ff 8d 45 d8 e8 ?? ?? ff ff ff 75 d8 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 dc ba 03 00 00 00 e8 ?? ?? ff ff 8b 55 dc b8 ?? ?? ?? ?? e8 ?? ?? ff ff 84 c0 74 2c 8d 45 d0 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*10) >=13
 
}