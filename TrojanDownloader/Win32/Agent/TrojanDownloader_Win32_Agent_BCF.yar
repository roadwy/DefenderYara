
rule TrojanDownloader_Win32_Agent_BCF{
	meta:
		description = "TrojanDownloader:Win32/Agent.BCF,SIGNATURE_TYPE_PEHSTR,21 00 21 00 06 00 00 "
		
	strings :
		$a_01_0 = {22 20 67 6f 74 6f 20 52 65 70 65 61 74 0a 64 65 6c 20 22 00 22 0a 69 66 20 65 78 69 73 74 20 22 00 00 00 00 3a 52 65 70 65 61 74 0a 64 65 6c 20 22 00 00 00 63 3a 5c 74 65 6d 70 2e 62 61 74 } //10
		$a_01_1 = {5c 75 63 6c 65 61 6e 65 72 5f 73 65 74 75 70 2e 65 78 65 } //10 \ucleaner_setup.exe
		$a_01_2 = {5c 73 32 66 2e 65 78 65 } //10 \s2f.exe
		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //2 URLDownloadToFileA
		$a_01_4 = {5c 43 61 73 69 6e 6f 2e 69 63 6f } //1 \Casino.ico
		$a_01_5 = {5c 53 70 79 77 61 72 65 20 52 65 6d 6f 76 65 72 2e 69 63 6f } //1 \Spyware Remover.ico
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=33
 
}