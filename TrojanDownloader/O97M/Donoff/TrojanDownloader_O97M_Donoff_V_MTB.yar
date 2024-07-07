
rule TrojanDownloader_O97M_Donoff_V_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.V!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 70 6c 61 79 6d 65 73 61 64 65 6c 73 6f 6c 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 6f 66 66 2f 72 74 33 35 2e 65 78 65 } //1 https://playmesadelsol.com/wp-content/off/rt35.exe
		$a_81_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_81_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_81_3 = {43 6f 76 69 64 2d 31 39 } //1 Covid-19
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}