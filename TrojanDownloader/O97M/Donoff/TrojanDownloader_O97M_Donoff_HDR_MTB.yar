
rule TrojanDownloader_O97M_Donoff_HDR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.HDR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {77 77 77 2e 79 65 73 66 6f 72 6d 2e 63 6f 6d 2f 61 63 74 69 76 65 2f 73 65 61 72 63 68 4d 65 73 73 65 6e 67 65 72 2f 75 70 64 61 74 65 32 2f 73 65 61 72 63 68 4d 65 73 73 65 6e 67 65 72 5f 75 70 67 72 61 64 65 5f 78 2e 65 78 65 90 0a 53 00 68 74 74 70 3a 2f 2f 90 00 } //1
		$a_01_1 = {53 68 65 6c 6c 20 22 43 3a 5c 73 4d 65 73 73 65 6e 67 65 72 5c 73 65 61 72 63 68 4d 65 73 73 65 6e 67 65 72 5f 75 70 67 72 61 64 65 5f 78 2e 65 78 65 22 } //1 Shell "C:\sMessenger\searchMessenger_upgrade_x.exe"
		$a_01_2 = {2e 46 6f 6c 64 65 72 45 78 69 73 74 73 28 22 43 3a 5c 73 4d 65 73 73 65 6e 67 65 72 22 29 } //1 .FolderExists("C:\sMessenger")
		$a_01_3 = {4b 69 6c 6c 20 44 4c 6f 63 61 6c 46 69 6c 65 } //1 Kill DLocalFile
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}