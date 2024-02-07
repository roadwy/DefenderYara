
rule TrojanDownloader_O97M_Powdow_ER_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.ER!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 69 73 74 69 74 75 74 6f 62 70 61 73 63 61 6c 77 65 62 2e 69 74 2f 6d 79 6e 6f 74 65 73 63 6f 6d 2f 72 65 6e 6f 6f 76 6f 68 6f 73 74 69 6e 67 6c 69 6c 6e 75 78 61 64 76 61 6e 63 65 64 2e 70 68 70 } //01 00  https://istitutobpascalweb.it/mynotescom/renoovohostinglilnuxadvanced.php
		$a_01_1 = {43 3a 5c 52 50 4a 62 59 75 52 5c 70 76 72 44 47 56 71 5c 72 43 4c 47 6a 79 53 2e 65 78 } //01 00  C:\RPJbYuR\pvrDGVq\rCLGjyS.ex
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00  URLDownloadToFileA
	condition:
		any of ($a_*)
 
}