
rule TrojanDownloader_BAT_FormBook_G_MTB{
	meta:
		description = "TrojanDownloader:BAT/FormBook.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 0b 07 8e 69 0c 2b 90 01 01 06 07 08 91 6f 90 01 01 00 00 0a 08 25 17 59 0c 16 fe 90 01 01 2d 90 01 01 06 6f 90 01 01 00 00 0a 0b 07 0d 09 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}