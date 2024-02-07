
rule TrojanDownloader_O97M_TrickbotCrypt_SM_MTB{
	meta:
		description = "TrojanDownloader:O97M/TrickbotCrypt.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_00_1 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 41 } //01 00  CreateDirectoryA
		$a_00_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_00_3 = {68 74 74 70 3a 2f 2f 62 6f 72 67 65 72 6e 65 77 73 68 65 72 61 6c 64 2e 63 6f 6d 2f 41 4d 50 4c 69 6e 65 72 73 4f 6e 6c 69 6e 65 2f 6c 75 62 69 6f 75 73 69 6e 64 65 6e 64 65 74 73 2e 64 6c 6c } //01 00  http://borgernewsherald.com/AMPLinersOnline/lubiousindendets.dll
		$a_00_4 = {43 3a 5c 50 65 72 4c 6f 67 5c 48 65 6c 70 5c 77 73 61 70 78 } //00 00  C:\PerLog\Help\wsapx
	condition:
		any of ($a_*)
 
}