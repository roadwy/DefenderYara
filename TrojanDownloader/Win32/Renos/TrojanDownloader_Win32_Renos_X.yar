
rule TrojanDownloader_Win32_Renos_X{
	meta:
		description = "TrojanDownloader:Win32/Renos.X,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 37 00 07 00 00 "
		
	strings :
		$a_00_0 = {77 65 62 73 70 79 73 68 69 65 6c 64 2e 63 6f 6d } //5 webspyshield.com
		$a_00_1 = {68 74 74 70 3a 2f 2f 77 65 62 73 70 79 73 68 69 65 6c 64 2e 63 6f 6d 2f 61 2f 73 65 74 75 70 2e 65 78 65 } //5 http://webspyshield.com/a/setup.exe
		$a_00_2 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 69 6e 74 65 72 6e 65 74 20 73 65 74 74 69 6e 67 73 } //10 software\microsoft\windows\currentversion\internet settings
		$a_01_3 = {6e 65 74 73 75 70 70 2e 64 6c 6c } //10 netsupp.dll
		$a_01_4 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //10 InternetReadFile
		$a_01_5 = {69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 00 00 } //10
		$a_01_6 = {25 73 26 25 58 2e 25 58 2e 25 58 2e 25 58 2e 25 58 } //10 %s&%X.%X.%X.%X.%X
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10) >=55
 
}