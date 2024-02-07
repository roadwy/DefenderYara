
rule Trojan_BAT_FormBook_LHI_MTB{
	meta:
		description = "Trojan:BAT/FormBook.LHI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 13 06 12 06 28 90 01 03 0a 17 da 13 08 16 13 09 2b 6c 00 07 11 07 11 09 6f 90 01 03 0a 13 0a 11 0a 16 16 16 16 28 90 01 03 0a 28 90 01 03 0a 13 0b 11 0b 2c 42 00 19 8d 90 01 03 01 25 16 12 0a 28 51 00 00 0a 9c 25 17 12 0a 28 52 00 00 0a 9c 25 18 11 0a 8c 90 01 03 01 72 90 01 03 70 18 14 28 90 01 03 0a a5 90 01 03 01 9c 13 0c 08 11 0c 6f 90 01 03 0a 00 00 00 11 09 17 d6 13 09 11 09 11 08 fe 02 16 fe 01 13 0d 11 0d 2d 85 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 41 72 67 62 } //00 00  FromArgb
	condition:
		any of ($a_*)
 
}