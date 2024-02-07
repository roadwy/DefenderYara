
rule TrojanDownloader_Win32_Agent_KK{
	meta:
		description = "TrojanDownloader:Win32/Agent.KK,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 75 70 64 61 74 65 2e 78 69 61 6f 73 68 6f 75 70 65 69 78 75 6e 2e 63 6f 6d 2f 74 73 62 68 6f 2e 69 6e 69 } //01 00  http://update.xiaoshoupeixun.com/tsbho.ini
		$a_00_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_03_2 = {f7 d1 49 51 6a 29 b9 90 01 02 00 10 e8 90 01 02 00 00 50 68 24 0c 0b 83 56 ff 15 90 00 } //01 00 
		$a_01_3 = {6a 00 68 c0 d4 01 00 68 02 10 00 00 56 ff d7 } //00 00 
	condition:
		any of ($a_*)
 
}