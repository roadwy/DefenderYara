
rule Trojan_BAT_Crysan_PSGV_MTB{
	meta:
		description = "Trojan:BAT/Crysan.PSGV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {6f 32 00 00 0a 00 28 be 00 00 06 72 0c 0a 00 70 72 10 0a 00 70 6f 4e 01 00 0a 17 8d ba 00 00 01 25 16 1f 2d 9d 6f 0e 01 00 0a 13 06 11 06 8e 69 8d cd 00 00 01 13 07 16 13 0a 2b 18 11 07 11 0a 11 06 11 0a 9a 1f 10 28 4f 01 00 0a d2 9c 11 0a 17 58 13 0a 11 0a 11 06 8e 69 fe 04 13 0b 11 0b 2d da } //00 00 
	condition:
		any of ($a_*)
 
}