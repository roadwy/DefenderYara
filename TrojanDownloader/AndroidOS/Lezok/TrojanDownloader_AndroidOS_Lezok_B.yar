
rule TrojanDownloader_AndroidOS_Lezok_B{
	meta:
		description = "TrojanDownloader:AndroidOS/Lezok.B,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 64 61 74 61 73 79 73 74 65 6d 2f } //02 00  Lcom/android/datasystem/
		$a_01_1 = {41 70 43 6f 72 65 4c 6f 61 64 65 72 } //02 00  ApCoreLoader
		$a_01_2 = {41 70 45 6e 76 69 72 6f 6e 6d 65 6e 74 } //02 00  ApEnvironment
		$a_01_3 = {46 69 6c 65 44 6f 77 6e 6c 6f 61 64 54 68 72 65 61 64 } //02 00  FileDownloadThread
		$a_01_4 = {44 65 63 72 79 70 74 53 74 72 69 6e 67 } //00 00  DecryptString
	condition:
		any of ($a_*)
 
}