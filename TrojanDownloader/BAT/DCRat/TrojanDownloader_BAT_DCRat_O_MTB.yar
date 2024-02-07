
rule TrojanDownloader_BAT_DCRat_O_MTB{
	meta:
		description = "TrojanDownloader:BAT/DCRat.O!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {57 f5 02 28 09 07 00 00 00 00 00 00 00 00 00 00 01 00 00 00 53 00 00 00 1a 00 00 00 2e 00 00 00 ac } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_2 = {53 70 65 63 69 61 6c 46 6f 6c 64 65 72 } //00 00  SpecialFolder
	condition:
		any of ($a_*)
 
}