
rule TrojanDownloader_O97M_Tnega_AR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Tnega.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 CreateObject("WScript.Shell")
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_03_2 = {2f 2f 73 6d 61 72 74 73 63 72 65 65 6e 74 65 73 74 72 61 74 69 6e 67 73 32 2e 6e 65 74 2f 90 02 1f 2e 65 78 65 90 0a 4f 00 68 74 74 70 73 3a 90 00 } //5
		$a_01_3 = {2e 52 75 6e 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 2e } //1 .Run CreateObject("Scripting.FileSystemObject").
		$a_03_4 = {2e 65 78 65 22 90 0a 4f 00 68 74 74 70 73 3a 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*5+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}