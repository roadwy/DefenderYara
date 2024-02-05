
rule Trojan_BAT_FormBook_AIKN_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AIKN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0c 16 13 07 2b 15 08 11 07 07 11 07 9a 1f 10 28 90 01 03 0a 9c 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 90 00 } //01 00 
		$a_01_1 = {47 00 61 00 6d 00 65 00 5f 00 6f 00 66 00 5f 00 50 00 69 00 67 00 } //00 00 
	condition:
		any of ($a_*)
 
}