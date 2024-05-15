
rule TrojanDownloader_BAT_AsyncRat_CCHZ_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRat.CCHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 14 11 14 6f 90 01 01 00 00 0a 26 73 90 01 04 13 15 11 15 72 90 01 01 06 00 70 73 90 01 03 0a 06 07 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 73 90 01 01 00 00 0a 13 16 11 16 72 90 00 } //01 00 
		$a_01_1 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 43 00 4d 00 44 00 } //01 00  DisableCMD
		$a_01_2 = {53 00 69 00 64 00 65 00 6c 00 6f 00 61 00 64 00 } //00 00  Sideload
	condition:
		any of ($a_*)
 
}