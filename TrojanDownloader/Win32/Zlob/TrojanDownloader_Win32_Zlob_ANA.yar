
rule TrojanDownloader_Win32_Zlob_ANA{
	meta:
		description = "TrojanDownloader:Win32/Zlob.ANA,SIGNATURE_TYPE_PEHSTR,2a 00 2a 00 06 00 00 "
		
	strings :
		$a_01_0 = {61 6c 6c 65 72 74 32 } //10 allert2
		$a_01_1 = {54 68 65 20 63 6f 6d 70 75 74 65 72 20 68 61 73 20 62 65 65 6e 20 69 6e 66 65 63 74 65 64 21 21 } //10 The computer has been infected!!
		$a_01_2 = {6d 79 66 69 72 73 74 67 61 79 73 65 78 2e 63 6f 6d 2f } //10 myfirstgaysex.com/
		$a_01_3 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 29 } //10 Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
		$a_01_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 41 } //1 ShellExecuteExA
		$a_01_5 = {49 6e 74 65 72 6e 65 74 43 6c 6f 73 65 48 61 6e 64 6c 65 } //1 InternetCloseHandle
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=42
 
}