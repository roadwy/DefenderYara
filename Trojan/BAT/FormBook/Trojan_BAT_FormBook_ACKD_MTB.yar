
rule Trojan_BAT_FormBook_ACKD_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ACKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {04 8e 69 5d 93 7e 90 01 03 04 07 91 61 d2 9c 00 07 17 58 90 00 } //01 00 
		$a_01_1 = {54 00 72 00 75 00 6d 00 70 00 5f 00 61 00 6e 00 64 00 5f 00 6a 00 6f 00 65 00 5f 00 62 00 69 00 64 00 65 00 6e 00 5f 00 70 00 6e 00 67 00 } //00 00 
	condition:
		any of ($a_*)
 
}