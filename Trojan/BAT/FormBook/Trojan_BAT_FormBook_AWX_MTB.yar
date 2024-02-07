
rule Trojan_BAT_FormBook_AWX_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AWX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {08 09 11 04 28 90 01 03 06 13 05 11 05 28 90 01 03 06 13 06 07 06 11 06 d2 9c 00 11 04 17 58 90 00 } //01 00 
		$a_01_1 = {41 00 6d 00 62 00 72 00 79 00 } //01 00  Ambry
		$a_01_2 = {47 65 74 50 69 78 65 6c } //00 00  GetPixel
	condition:
		any of ($a_*)
 
}