
rule Trojan_BAT_Androm_EAOX_MTB{
	meta:
		description = "Trojan:BAT/Androm.EAOX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 11 06 11 07 11 06 11 07 91 19 63 11 06 11 07 91 1b 62 60 d2 9c 11 06 11 07 8f 1c 00 00 01 25 47 03 11 07 91 61 d2 52 00 11 07 17 58 13 07 11 07 06 fe 04 13 08 11 08 2d c6 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}