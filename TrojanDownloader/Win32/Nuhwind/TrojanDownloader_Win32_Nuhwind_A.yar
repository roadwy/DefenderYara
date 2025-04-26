
rule TrojanDownloader_Win32_Nuhwind_A{
	meta:
		description = "TrojanDownloader:Win32/Nuhwind.A,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {6c 69 6e 6b 31 2e 6d 32 61 2e 63 6f 2e 6b 72 2f 6e 68 76 77 69 6e 64 2f 63 6f 75 6e 74 33 2e 70 68 70 3f 4d 4f 44 45 3d 31 26 } //1 link1.m2a.co.kr/nhvwind/count3.php?MODE=1&
		$a_01_1 = {6c 69 6e 6b 31 2e 6d 32 61 2e 63 6f 2e 6b 72 2f 6e 68 76 77 69 6e 64 2f 63 6f 75 6e 74 33 2e 70 68 70 3f 4d 4f 44 45 3d 33 26 } //1 link1.m2a.co.kr/nhvwind/count3.php?MODE=3&
		$a_01_2 = {6c 69 6e 6b 31 2e 6d 32 61 2e 63 6f 2e 6b 72 2f 6e 68 76 77 69 6e 64 2f 63 6f 75 6e 74 33 2e 70 68 70 3f 4d 4f 44 45 3d 35 26 } //1 link1.m2a.co.kr/nhvwind/count3.php?MODE=5&
		$a_01_3 = {6e 68 76 69 6e 69 74 2e 65 78 65 } //1 nhvinit.exe
		$a_01_4 = {6e 68 76 77 69 6e 64 4d 61 69 6e } //1 nhvwindMain
		$a_01_5 = {6e 68 76 77 69 6e 64 2e 65 78 65 } //1 nhvwind.exe
		$a_01_6 = {6e 68 76 69 6e 69 74 30 30 2e 65 78 65 } //1 nhvinit00.exe
		$a_01_7 = {53 6f 66 74 77 61 72 65 5c 6e 68 76 77 69 6e 64 } //1 Software\nhvwind
		$a_01_8 = {41 64 72 4d 63 4d 61 69 6e } //1 AdrMcMain
		$a_01_9 = {41 64 72 4d 63 2e 65 78 65 } //1 AdrMc.exe
		$a_01_10 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 43 61 63 68 65 46 69 6c 65 41 } //1 URLDownloadToCacheFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}