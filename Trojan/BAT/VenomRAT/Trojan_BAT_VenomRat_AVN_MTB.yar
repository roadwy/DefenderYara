
rule Trojan_BAT_VenomRat_AVN_MTB{
	meta:
		description = "Trojan:BAT/VenomRat.AVN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 07 2b 29 11 06 11 07 e0 58 11 04 11 07 91 52 11 06 11 07 e0 58 47 11 04 11 07 91 fe 01 16 fe 01 13 08 11 08 2d dd 11 07 17 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}