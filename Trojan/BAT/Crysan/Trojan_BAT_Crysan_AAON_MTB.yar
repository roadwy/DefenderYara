
rule Trojan_BAT_Crysan_AAON_MTB{
	meta:
		description = "Trojan:BAT/Crysan.AAON!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0c 2b 13 00 07 08 07 08 91 20 81 02 00 00 59 d2 9c 00 08 17 58 0c 08 07 8e 69 fe 04 0d 09 2d e3 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}