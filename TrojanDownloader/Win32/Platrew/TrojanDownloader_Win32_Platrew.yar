
rule TrojanDownloader_Win32_Platrew{
	meta:
		description = "TrojanDownloader:Win32/Platrew,SIGNATURE_TYPE_PEHSTR_EXT,20 00 1e 00 06 00 00 "
		
	strings :
		$a_00_0 = {70 6c 61 74 69 6e 75 6d 72 65 77 61 72 64 2e 63 6f 2e 6b 72 2f 76 65 72 73 69 6f 6e 2f 73 76 63 76 65 72 2e 70 68 70 } //10 platinumreward.co.kr/version/svcver.php
		$a_00_1 = {75 70 64 61 74 65 2e 70 6c 61 74 69 6e 75 6d 72 65 77 61 72 64 2e 63 6f 2e 6b 72 2f 70 6c 61 74 69 6e 75 6d 2f 62 61 63 6b 6d 61 6e 2f 62 64 6b 73 76 63 2e 65 78 65 } //10 update.platinumreward.co.kr/platinum/backman/bdksvc.exe
		$a_00_2 = {75 70 64 61 74 65 2e 70 6c 61 74 69 6e 75 6d 72 65 77 61 72 64 2e 63 6f 2e 6b 72 2f 73 75 62 58 2f 48 44 61 71 2e 65 78 65 } //10 update.platinumreward.co.kr/subX/HDaq.exe
		$a_00_3 = {75 70 64 61 74 65 2e 70 6c 61 74 69 6e 75 6d 72 65 77 61 72 64 2e 63 6f 2e 6b 72 2f 70 6c 61 74 69 6e 75 6d 2f 62 61 63 6b 6d 61 6e 2f 72 65 63 6f 76 65 72 79 2e 65 78 65 } //10 update.platinumreward.co.kr/platinum/backman/recovery.exe
		$a_01_4 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
		$a_01_5 = {49 6e 74 65 72 6e 65 74 43 6c 6f 73 65 48 61 6e 64 6c 65 } //1 InternetCloseHandle
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=30
 
}