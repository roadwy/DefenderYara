
rule Trojan_BAT_FormBook_ACK_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ACK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 1e 08 11 04 9a 13 08 09 11 08 1f 10 28 90 01 03 0a b4 6f 90 01 03 0a 00 11 04 17 d6 13 04 00 11 04 08 8e 69 fe 04 13 09 11 09 2d d5 90 00 } //01 00 
		$a_01_1 = {5a 00 38 00 30 00 4e 00 61 00 76 00 42 00 61 00 72 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}