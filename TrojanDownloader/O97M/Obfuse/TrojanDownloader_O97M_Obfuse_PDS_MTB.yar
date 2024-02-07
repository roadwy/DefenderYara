
rule TrojanDownloader_O97M_Obfuse_PDS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PDS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 62 6f 6f 6b 69 71 2e 62 73 6e 6c 2e 63 6f 2e 69 6e 2f 64 61 74 61 5f 65 6e 74 72 79 2f 63 69 72 63 75 6c 61 72 73 2f 6d 61 63 2e 65 78 65 } //01 00  http://www.bookiq.bsnl.co.in/data_entry/circulars/mac.exe
		$a_01_1 = {53 68 65 6c 6c 20 28 22 66 69 6c 65 31 2e 65 78 65 22 29 } //01 00  Shell ("file1.exe")
		$a_01_2 = {3d 20 45 6e 76 69 72 6f 6e 28 22 61 70 70 64 61 74 61 22 29 } //00 00  = Environ("appdata")
	condition:
		any of ($a_*)
 
}