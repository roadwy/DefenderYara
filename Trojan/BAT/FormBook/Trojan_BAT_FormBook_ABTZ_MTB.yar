
rule Trojan_BAT_FormBook_ABTZ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABTZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {16 13 20 2b 25 11 1e 11 20 18 28 90 01 02 00 06 20 03 02 00 00 28 90 01 01 00 00 0a 13 22 11 1f 11 22 6f 90 01 01 00 00 0a 11 20 18 58 13 20 11 20 11 1e 28 90 01 02 00 06 32 d0 90 00 } //01 00 
		$a_01_1 = {47 00 61 00 73 00 74 00 72 00 6f 00 65 00 6e 00 74 00 65 00 72 00 6f 00 6c 00 6f 00 67 00 79 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00  Gastroenterology.Properties.Resources
	condition:
		any of ($a_*)
 
}