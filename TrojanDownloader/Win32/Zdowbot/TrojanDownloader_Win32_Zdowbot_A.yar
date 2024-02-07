
rule TrojanDownloader_Win32_Zdowbot_A{
	meta:
		description = "TrojanDownloader:Win32/Zdowbot.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 cd cc cc cc f7 e1 c1 ea 03 8d 04 92 03 c0 8b d1 2b d0 8a 82 90 01 03 00 30 04 39 41 3b ce 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Zdowbot_A_2{
	meta:
		description = "TrojanDownloader:Win32/Zdowbot.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 44 24 13 76 c7 44 24 1c 40 00 00 00 c7 44 24 14 71 00 00 00 bf 7e 00 00 00 c7 44 24 20 15 00 00 00 } //01 00 
		$a_01_1 = {8b d5 6b d2 76 b8 91 73 9f 5d f7 e2 } //00 00 
		$a_00_2 = {78 } //c3 00  x
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Zdowbot_A_3{
	meta:
		description = "TrojanDownloader:Win32/Zdowbot.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {2f 67 61 74 65 2e 70 68 70 7c 68 74 74 70 3a 2f 2f 90 02 20 2e 72 75 2f 90 02 06 2f 67 61 74 65 2e 70 68 70 7c 68 74 74 70 3a 2f 2f 90 00 } //01 00 
		$a_03_1 = {2f 6c 73 35 2f 66 6f 72 75 6d 2e 70 68 70 7c 68 74 74 70 3a 2f 2f 90 02 20 2e 72 75 2f 90 02 06 2f 66 6f 72 75 6d 2e 70 68 70 7c 68 74 74 70 3a 2f 2f 90 02 20 2e 72 75 2f 90 1b 01 2f 66 6f 72 75 6d 2e 70 68 70 90 00 } //02 00 
		$a_01_2 = {47 55 49 44 3d 25 49 36 34 75 26 42 55 49 4c 44 3d 25 73 26 49 4e 46 4f 3d 25 73 26 49 50 3d 25 73 26 54 59 50 45 3d 31 26 57 49 4e 3d 25 64 2e 25 64 28 25 73 29 } //00 00  GUID=%I64u&BUILD=%s&INFO=%s&IP=%s&TYPE=1&WIN=%d.%d(%s)
		$a_00_3 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}