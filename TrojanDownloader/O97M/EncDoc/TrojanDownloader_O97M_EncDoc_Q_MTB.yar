
rule TrojanDownloader_O97M_EncDoc_Q_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.Q!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 66 61 6f 67 2e 6f 72 67 2e 68 6b 2f 73 63 61 6e 6e 65 72 2f 6f 76 65 72 77 61 74 63 68 2e 70 68 70 } //01 00  https://faog.org.hk/scanner/overwatch.php
		$a_03_1 = {68 74 74 70 3a 2f 2f 73 65 72 76 69 63 65 2e 70 61 6e 64 74 65 6c 65 63 74 72 69 63 2e 63 6f 6d 2f 90 02 10 2e 65 78 65 90 00 } //01 00 
		$a_03_2 = {50 72 6f 67 72 61 6d 44 61 74 61 5c 90 02 10 2e 65 78 65 90 00 } //01 00 
		$a_01_3 = {55 52 4c 4d 4f 4e } //01 00  URLMON
		$a_01_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_01_5 = {53 68 65 6c 6c 33 32 } //01 00  Shell32
		$a_01_6 = {53 68 65 6c 6c 45 78 65 63 } //00 00  ShellExec
	condition:
		any of ($a_*)
 
}