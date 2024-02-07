
rule TrojanDownloader_O97M_Lokibot_NB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Lokibot.NB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 70 69 72 61 74 65 73 6d 6f 6b 65 72 2e 63 6f 6d 2f 70 75 72 63 68 61 73 65 25 32 30 6f 72 64 65 72 2f 50 75 72 63 68 61 73 65 25 32 30 4f 72 64 65 72 2e 65 78 65 } //01 00  http://piratesmoker.com/purchase%20order/Purchase%20Order.exe
		$a_00_1 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 77 6e 6c 6f 61 64 73 5c 22 20 2b 22 63 68 72 64 74 79 6d 65 6d 6e 6e 79 63 62 75 6c 78 61 68 62 68 68 61 63 6b 72 79 6e 6b 6a 6e 65 62 74 74 64 6f 6c 62 69 66 79 70 61 63 2e 65 78 65 } //01 00  C:\Users\Public\Downloads\" +"chrdtymemnnycbulxahbhhackrynkjnebttdolbifypac.exe
		$a_02_2 = {3d 20 53 68 65 6c 6c 28 90 02 32 2c 20 76 62 4e 6f 72 6d 61 6c 4e 6f 46 6f 63 75 73 90 00 } //01 00 
		$a_00_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_00_4 = {75 72 6c 6d 6f 6e } //00 00  urlmon
	condition:
		any of ($a_*)
 
}