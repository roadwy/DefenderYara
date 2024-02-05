
rule Trojan_BAT_BitRat_NEAA_MTB{
	meta:
		description = "Trojan:BAT/BitRat.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {0a 2b 1b 00 7e 02 00 00 04 06 7e 02 00 00 04 06 91 20 6f 02 00 00 59 d2 9c 00 06 17 58 0a 06 7e 02 00 00 04 8e 69 fe 04 0b 07 2d d7 } //02 00 
		$a_01_1 = {6c 00 75 00 63 00 69 00 64 00 73 00 6f 00 66 00 74 00 65 00 63 00 68 00 } //00 00 
	condition:
		any of ($a_*)
 
}