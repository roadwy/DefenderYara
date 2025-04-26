
rule Trojan_BAT_Crysan_EAXO_MTB{
	meta:
		description = "Trojan:BAT/Crysan.EAXO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 73 56 00 00 0a 0a 16 0b 2b 1d 00 06 72 fb 07 00 70 07 8c 45 00 00 01 28 36 00 00 0a 6f 57 00 00 0a 26 00 07 17 58 0b 07 20 e8 03 00 00 fe 04 0c 08 2d d7 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}