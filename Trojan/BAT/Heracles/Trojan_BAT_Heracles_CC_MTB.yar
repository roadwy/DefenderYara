
rule Trojan_BAT_Heracles_CC_MTB{
	meta:
		description = "Trojan:BAT/Heracles.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 05 11 05 16 fe 03 16 fe 01 13 08 11 08 2d 04 07 17 58 0b 11 05 16 fe 01 16 fe 01 13 08 11 08 2d 02 2b 12 00 11 04 17 58 13 04 11 04 1b fe 04 13 08 11 08 2d c3 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}