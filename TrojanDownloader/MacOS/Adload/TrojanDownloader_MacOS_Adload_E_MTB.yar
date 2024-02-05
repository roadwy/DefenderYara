
rule TrojanDownloader_MacOS_Adload_E_MTB{
	meta:
		description = "TrojanDownloader:MacOS/Adload.E!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 73 70 65 6c 6c 69 6e 67 2e 63 68 65 63 6b 65 72 2e 41 67 65 6e 74 } //01 00 
		$a_01_1 = {2f 74 6d 70 2f 75 70 75 70 32 } //01 00 
		$a_01_2 = {2f 62 69 6e 2f 73 68 20 2d 63 20 20 22 2f 62 69 6e 2f 63 68 6d 6f 64 20 37 37 37 } //01 00 
		$a_01_3 = {2d 6e 6f 62 72 6f 77 73 65 } //00 00 
	condition:
		any of ($a_*)
 
}