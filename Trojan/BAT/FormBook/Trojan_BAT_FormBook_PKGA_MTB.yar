
rule Trojan_BAT_FormBook_PKGA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.PKGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {13 05 08 09 11 04 6f 90 01 03 0a 13 06 11 06 28 90 01 03 0a 13 07 07 06 11 07 d2 9c 00 11 04 17 58 90 00 } //01 00 
		$a_01_1 = {42 00 6c 00 61 00 63 00 6b 00 48 00 61 00 77 00 6b 00 44 00 6f 00 77 00 6e 00 } //01 00  BlackHawkDown
		$a_01_2 = {47 65 74 50 69 78 65 6c } //00 00  GetPixel
	condition:
		any of ($a_*)
 
}