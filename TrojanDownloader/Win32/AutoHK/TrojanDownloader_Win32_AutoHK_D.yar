
rule TrojanDownloader_Win32_AutoHK_D{
	meta:
		description = "TrojanDownloader:Win32/AutoHK.D,SIGNATURE_TYPE_PEHSTR,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2f 68 52 31 69 77 6d 71 62 } //2 https://pastebin.com/raw/hR1iwmqb
		$a_01_1 = {52 75 6e 57 61 69 74 20 70 6f 77 65 72 73 68 65 6c 6c 20 2d 6e 6f 65 78 69 74 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 68 69 64 64 65 6e } //1 RunWait powershell -noexit -windowstyle hidden
		$a_01_2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 77 00 69 00 6b 00 6e 00 65 00 74 00 2e 00 77 00 69 00 6b 00 61 00 62 00 61 00 2e 00 63 00 6f 00 6d 00 } //2 https://wiknet.wikaba.com
		$a_01_3 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 63 00 68 00 65 00 63 00 6b 00 74 00 65 00 73 00 74 00 2e 00 77 00 77 00 77 00 31 00 2e 00 62 00 69 00 7a 00 } //2 https://checktest.www1.biz
		$a_01_4 = {2f 00 46 00 65 00 65 00 64 00 42 00 61 00 63 00 6b 00 2e 00 70 00 68 00 70 00 } //1 /FeedBack.php
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=3
 
}