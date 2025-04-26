
rule TrojanDownloader_O97M_Donoff_AN{
	meta:
		description = "TrojanDownloader:O97M/Donoff.AN,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 41 6c 69 61 73 20 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 20 28 42 79 56 61 6c } //1 Lib "urlmon" Alias "URLDownloadToFileA" (ByVal
		$a_00_1 = {2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 22 25 54 45 4d 50 25 22 29 20 2b } //1 .ExpandEnvironmentStrings("%TEMP%") +
		$a_00_2 = {20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1  = CreateObject("WScript.Shell")
		$a_00_3 = {54 6f 20 4c 65 6e 28 22 6f 7b 7b 77 41 36 36 } //1 To Len("o{{wA66
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}