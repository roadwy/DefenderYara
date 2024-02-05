
rule Trojan_BAT_FormBook_NYP_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NYP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {08 07 09 07 8e 69 5d 91 06 09 91 61 d2 2b 06 09 17 58 0d 2b 07 6f } //01 00 
		$a_01_1 = {66 00 69 00 6c 00 74 00 68 00 79 00 2d 00 72 00 65 00 67 00 72 00 65 00 74 00 2e 00 64 00 76 00 72 00 6c 00 69 00 73 00 74 00 73 00 2e 00 63 00 } //00 00 
	condition:
		any of ($a_*)
 
}