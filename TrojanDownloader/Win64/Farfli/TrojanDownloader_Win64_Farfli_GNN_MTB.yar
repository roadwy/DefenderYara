
rule TrojanDownloader_Win64_Farfli_GNN_MTB{
	meta:
		description = "TrojanDownloader:Win64/Farfli.GNN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {31 35 36 2e 32 33 34 2e 36 35 } //1 156.234.65
		$a_01_1 = {5c 44 6f 63 75 6d 65 6e 74 73 5c 73 76 63 68 6f 73 74 2e 74 78 74 } //1 \Documents\svchost.txt
		$a_01_2 = {5c 44 6f 63 75 6d 65 6e 74 73 5c 31 2e 72 61 72 } //1 \Documents\1.rar
		$a_01_3 = {5c 44 6f 63 75 6d 65 6e 74 73 5c 6a 64 69 2e 6c 6e 6b } //1 \Documents\jdi.lnk
		$a_01_4 = {5c 52 65 6c 65 61 73 65 5c 73 64 61 73 64 61 73 64 2e 70 64 62 } //1 \Release\sdasdasd.pdb
		$a_01_5 = {50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 37 7a 2e 65 78 65 } //1 Public\Documents\7z.exe
		$a_80_6 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 37 7a 2e 65 78 65 } //C:\ProgramData\7z.exe  1
		$a_01_7 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 } //1 URLDownloadToFile
		$a_01_8 = {53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 ShellExecute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_80_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}