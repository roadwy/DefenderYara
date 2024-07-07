
rule Trojan_BAT_Crysan_SZK_MTB{
	meta:
		description = "Trojan:BAT/Crysan.SZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 06 00 00 04 06 7e 06 00 00 04 06 91 20 90 01 03 00 59 d2 9c 00 06 17 58 0a 06 7e 06 00 00 04 8e 69 fe 04 0b 07 2d d7 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}