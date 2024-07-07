
rule TrojanDownloader_Win32_Agent_IJ{
	meta:
		description = "TrojanDownloader:Win32/Agent.IJ,SIGNATURE_TYPE_PEHSTR,33 00 33 00 0a 00 00 "
		
	strings :
		$a_01_0 = {73 74 61 72 74 20 68 74 74 70 3a 2f 2f } //10 start http://
		$a_01_1 = {2f 63 20 65 63 68 6f 20 61 20 3e 20 5c 53 79 73 74 65 6d 33 32 5c } //10 /c echo a > \System32\
		$a_01_2 = {5c 63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20 5c 53 79 73 74 65 6d 33 32 5c 77 69 6e 6e 33 32 74 2e 65 78 65 } //10 \cmd.exe /c start \System32\winn32t.exe
		$a_01_3 = {43 72 65 61 74 65 53 65 72 76 69 63 65 41 } //10 CreateServiceA
		$a_01_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //10 URLDownloadToFileA
		$a_01_5 = {62 6c 6f 75 6b 61 73 73 73 } //1 bloukasss
		$a_01_6 = {77 69 6e 7a 7a 2e 65 78 65 } //1 winzz.exe
		$a_01_7 = {77 69 6e 6e 33 32 74 2e 65 78 65 } //1 winn32t.exe
		$a_01_8 = {38 31 2e 32 30 39 2e 31 31 32 2e } //1 81.209.112.
		$a_01_9 = {42 6c 6f 63 6b 70 6f 72 6e 61 63 63 65 73 73 } //1 Blockpornaccess
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=51
 
}