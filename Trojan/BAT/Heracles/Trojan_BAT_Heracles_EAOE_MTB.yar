
rule Trojan_BAT_Heracles_EAOE_MTB{
	meta:
		description = "Trojan:BAT/Heracles.EAOE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 28 06 00 00 0a 06 6f 07 00 00 0a 28 08 00 00 0a 28 09 00 00 0a 0b 07 72 01 00 00 70 6f 0a 00 00 0a 0c 08 17 8d 10 00 00 01 13 04 11 04 16 d0 11 00 00 01 28 0b 00 00 0a a2 11 04 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}