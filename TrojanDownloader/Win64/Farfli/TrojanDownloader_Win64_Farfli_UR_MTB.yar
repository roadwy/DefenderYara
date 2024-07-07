
rule TrojanDownloader_Win64_Farfli_UR_MTB{
	meta:
		description = "TrojanDownloader:Win64/Farfli.UR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 31 39 34 2e 31 34 36 2e 38 34 2e 32 34 33 3a 34 33 39 37 2f 37 37 } //1 http://194.146.84.243:4397/77
		$a_01_1 = {5c 72 75 6e 64 6c 6c 33 32 32 32 2e 65 78 65 } //1 \rundll3222.exe
		$a_01_2 = {6f 6a 62 6b 63 67 2e 65 78 65 } //1 ojbkcg.exe
		$a_01_3 = {5c 73 76 63 68 6f 73 74 2e 74 78 74 } //1 \svchost.txt
		$a_01_4 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 73 76 63 68 6f 73 74 2e 74 78 74 } //1 C:\ProgramData\svchost.txt
		$a_01_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 } //1 URLDownloadToFile
		$a_01_6 = {53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 ShellExecute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}