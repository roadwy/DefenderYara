
rule TrojanDownloader_BAT_FormBook_H_MTB{
	meta:
		description = "TrojanDownloader:BAT/FormBook.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 8e 69 0c 2b 90 01 01 07 06 08 91 6f 90 01 01 00 00 0a 08 25 17 59 0c 16 fe 90 01 01 2d 90 01 01 07 6f 90 01 01 00 00 0a 0a 06 0d 09 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}