
rule TrojanDownloader_Win32_Delf_CT{
	meta:
		description = "TrojanDownloader:Win32/Delf.CT,SIGNATURE_TYPE_PEHSTR,21 00 21 00 07 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 66 72 65 65 2d 73 65 72 76 69 63 65 2e 6b 69 72 2e 6a 70 2f 65 78 65 78 65 2f } //10 http://free-service.kir.jp/exexe/
		$a_01_1 = {4d 65 65 50 6c 61 79 65 72 } //10 MeePlayer
		$a_01_2 = {53 65 72 76 69 63 65 50 61 63 6b 2e 65 78 65 } //10 ServicePack.exe
		$a_01_3 = {68 74 74 70 3a 2f 2f 6e 61 74 75 72 61 6c 39 2d 32 6e 64 2e 63 6f 6d 2f 53 57 46 2f } //1 http://natural9-2nd.com/SWF/
		$a_01_4 = {73 6f 66 74 77 61 72 65 5c 62 6f 72 6c 61 6e 64 5c 64 65 6c 70 68 69 5c 72 74 6c } //1 software\borland\delphi\rtl
		$a_01_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_6 = {73 68 65 6c 6c 65 78 65 63 75 74 65 61 } //1 shellexecutea
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=33
 
}