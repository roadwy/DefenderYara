
rule TrojanDownloader_O97M_Nemucod_PC_MSR{
	meta:
		description = "TrojanDownloader:O97M/Nemucod.PC!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,1c 00 1c 00 06 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 90 02 01 3a 2f 2f 90 02 03 2e 90 02 03 2e 90 02 03 2e 90 02 03 2f 63 72 79 70 74 2e 64 6c 6c 90 00 } //10
		$a_03_1 = {43 3a 5c 72 6e 63 77 6e 65 72 5c 90 02 0f 2e 64 6c 6c 20 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 90 00 } //10
		$a_01_2 = {55 52 4c 4d 4f 4e } //2 URLMON
		$a_01_3 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //2 rundll32.exe
		$a_01_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //2 URLDownloadToFileA
		$a_01_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //2 ShellExecuteA
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=28
 
}