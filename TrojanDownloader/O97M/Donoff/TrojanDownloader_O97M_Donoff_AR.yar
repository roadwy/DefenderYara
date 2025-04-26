
rule TrojanDownloader_O97M_Donoff_AR{
	meta:
		description = "TrojanDownloader:O97M/Donoff.AR,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 41 6c 69 61 73 20 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 20 28 42 79 56 61 6c } //1 Lib "urlmon" Alias "URLDownloadToFileA" (ByVal
		$a_00_1 = {20 54 6f 20 4c 65 6e 28 22 } //1  To Len("
		$a_00_2 = {3d 20 4d 69 64 28 22 } //1 = Mid("
		$a_00_3 = {2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 53 74 72 52 65 76 65 72 73 65 28 22 25 50 4d 45 54 25 22 29 29 20 2b } //1 .ExpandEnvironmentStrings(StrReverse("%PMET%")) +
		$a_00_4 = {3d 20 43 68 72 28 41 73 63 28 } //1 = Chr(Asc(
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}