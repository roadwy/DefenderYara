
rule Trojan_BAT_FormBook_AHNX_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AHNX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {09 15 fe 01 13 04 11 04 2c 12 00 02 28 90 01 03 06 07 6f 90 01 03 06 0b 17 0c 2b 26 02 28 90 01 03 06 09 9a 08 16 32 03 16 2b 01 17 6f 90 01 03 06 00 02 28 90 01 03 06 09 9a 07 6f 90 00 } //01 00 
		$a_01_1 = {45 00 6e 00 69 00 67 00 6d 00 61 00 } //00 00  Enigma
	condition:
		any of ($a_*)
 
}