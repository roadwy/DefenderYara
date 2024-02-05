
rule TrojanDownloader_O97M_EncDoc_SMQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SMQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 78 65 2e 30 32 34 39 35 30 30 32 25 4f 50 2f 6b 72 61 6c 43 30 32 25 6c 75 61 50 2f 6d 6f 63 2e 6d 61 6b 63 69 6c 63 74 73 75 6a 2f 2f 3a 73 70 74 74 68 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_EncDoc_SMQ_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SMQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {2d 77 20 68 69 20 73 6c 5e 65 65 70 20 2d 53 65 20 33 31 3b 53 74 90 02 01 61 5e 72 74 2d 42 69 74 73 54 72 5e 61 6e 73 5e 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 60 70 90 02 9f 2e 65 60 78 65 20 2d 44 65 73 74 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 90 02 20 2e 65 60 78 65 3b 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 90 1b 02 2e 65 60 78 65 90 00 } //05 00 
		$a_03_1 = {2d 77 20 68 69 20 90 02 ff 20 2d 53 6f 75 72 63 65 20 68 74 74 60 70 90 02 9f 2e 65 60 78 65 20 2d 44 65 73 74 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 90 02 9f 2e 65 60 78 65 3b 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 90 1b 02 2e 65 60 78 65 90 00 } //01 00 
		$a_01_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //01 00 
		$a_01_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 57 } //00 00 
	condition:
		any of ($a_*)
 
}