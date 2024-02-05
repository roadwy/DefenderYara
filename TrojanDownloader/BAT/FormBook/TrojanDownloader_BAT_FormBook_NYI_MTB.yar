
rule TrojanDownloader_BAT_FormBook_NYI_MTB{
	meta:
		description = "TrojanDownloader:BAT/FormBook.NYI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {09 08 11 04 08 8e 69 5d 91 06 11 04 91 61 d2 } //01 00 
		$a_01_1 = {95 b6 29 09 0b 00 00 00 da a4 21 00 16 00 00 01 00 00 00 35 00 00 00 08 00 00 00 07 00 00 00 14 00 00 00 0a 00 00 00 3f } //00 00 
	condition:
		any of ($a_*)
 
}