
rule TrojanDownloader_Win32_Agent_BCK{
	meta:
		description = "TrojanDownloader:Win32/Agent.BCK,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_00_0 = {8b 8c 24 30 01 00 00 8b 9c 24 2c 01 00 00 8b e9 8b d0 33 c0 8b fb c1 e9 02 f3 ab 8b cd 89 54 24 10 83 e1 03 83 fa 01 f3 aa 74 0e 83 fa 02 74 09 8b bc 24 28 01 00 00 eb 75 8b 56 04 8d 44 24 14 50 68 19 00 02 00 8d 4e 0c 6a 00 51 52 ff 15 } //10
		$a_02_1 = {68 74 74 70 3a 2f 2f [0-20] 2f 70 72 6f 67 72 61 6d 2f 90 05 40 0d 61 2d 7a 41 2d 5a 30 2d 39 2e 5f 2f 2d 53 65 74 75 70 2e 65 78 65 } //10
		$a_01_2 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10+(#a_01_2  & 1)*1) >=21
 
}