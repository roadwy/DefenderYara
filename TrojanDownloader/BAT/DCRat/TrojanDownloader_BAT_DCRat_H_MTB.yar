
rule TrojanDownloader_BAT_DCRat_H_MTB{
	meta:
		description = "TrojanDownloader:BAT/DCRat.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 25 16 6f 90 01 01 00 00 0a 74 90 01 01 00 00 01 90 02 02 25 90 02 02 72 90 01 01 00 00 70 6f 90 01 01 00 00 0a 72 90 01 01 00 00 70 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 25 17 6f 90 01 01 00 00 0a 75 90 01 01 00 00 01 90 02 02 25 d0 90 01 01 00 00 01 28 90 01 01 00 00 0a 90 02 02 28 90 01 01 00 00 06 74 90 01 01 00 00 01 6f 90 01 01 00 00 0a 25 18 6f 90 00 } //02 00 
		$a_03_1 = {8e 69 5d 91 03 90 02 02 91 61 d2 9c 90 00 } //01 00 
		$a_01_2 = {67 65 74 5f 41 53 43 49 49 } //01 00  get_ASCII
		$a_01_3 = {47 65 74 42 79 74 65 73 } //00 00  GetBytes
	condition:
		any of ($a_*)
 
}