
rule TrojanDownloader_Win32_Renos_ET{
	meta:
		description = "TrojanDownloader:Win32/Renos.ET,SIGNATURE_TYPE_PEHSTR,06 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {49 6e 73 74 61 6c 6c 69 6e 67 20 53 70 79 77 61 72 65 20 53 6f 66 74 20 53 74 6f 70 } //1 Installing Spyware Soft Stop
		$a_01_1 = {68 74 74 70 3a 2f 2f 6c 6f 63 61 6c 68 6f 73 74 2f 73 73 73 5f 2f 64 6f 77 6e 6c 6f 61 64 73 2f 69 6e 73 74 61 6c 6c 2e 65 78 65 } //1 http://localhost/sss_/downloads/install.exe
		$a_01_2 = {50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 53 70 79 77 61 72 65 20 53 6f 66 74 20 53 74 6f 70 5c 53 70 79 77 61 72 65 20 53 6f 66 74 20 53 74 6f 70 2e 65 78 65 } //1 Program Files\Spyware Soft Stop\Spyware Soft Stop.exe
		$a_01_3 = {57 61 72 6e 69 6e 67 21 } //1 Warning!
		$a_01_4 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 69 73 20 70 72 6f 62 61 62 6c 79 20 69 6e 66 65 63 74 65 64 2e 20 4d 69 63 72 6f 73 6f 66 74 20 43 6f 72 70 6f 72 61 74 69 6f 6e 20 72 65 63 6f 6d 6d 65 6e 64 73 20 20 74 6f 20 63 68 65 63 6b 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 6f 6e 20 74 68 65 20 73 70 79 77 61 72 65 20 70 72 65 73 65 6e 74 60 73 2e 20 43 6c 69 63 6b 20 68 65 72 65 20 74 6f 20 64 6f 77 6e 6c 6f 61 64 20 75 70 64 61 74 65 73 } //1 Your computer is probably infected. Microsoft Corporation recommends  to check your computer on the spyware present`s. Click here to download updates
		$a_01_5 = {6e 6f 74 69 66 79 73 62 2e 64 6c 6c } //1 notifysb.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}