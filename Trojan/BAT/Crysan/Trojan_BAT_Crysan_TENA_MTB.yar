
rule Trojan_BAT_Crysan_TENA_MTB{
	meta:
		description = "Trojan:BAT/Crysan.TENA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0c 03 07 94 04 6f 90 01 03 0a 20 80 00 00 00 61 5b 0d 09 08 20 00 01 00 00 5a 16 60 59 d2 13 04 06 11 04 6f 90 01 03 0a 00 00 07 17 58 0b 07 03 8e 69 fe 04 13 05 11 05 2d bf 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}