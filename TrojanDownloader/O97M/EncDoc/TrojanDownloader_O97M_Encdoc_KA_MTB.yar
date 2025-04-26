
rule TrojanDownloader_O97M_Encdoc_KA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Encdoc.KA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 72 65 6d 73 6f 66 74 2e 69 74 2f 63 6f 6e 72 6f 6c 2f 70 61 63 6b 2e 70 68 70 } //1 https://www.remsoft.it/conrol/pack.php
		$a_00_1 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 76 4b 72 4a 75 79 5a 2e 65 78 65 } //1 C:\ProgramData\vKrJuyZ.exe
		$a_00_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_00_3 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 41 } //1 CreateDirectoryA
		$a_00_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}