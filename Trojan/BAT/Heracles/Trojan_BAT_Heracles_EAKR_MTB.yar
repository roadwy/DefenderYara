
rule Trojan_BAT_Heracles_EAKR_MTB{
	meta:
		description = "Trojan:BAT/Heracles.EAKR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 07 07 61 07 61 03 04 28 0a 00 00 06 00 07 17 58 0b 07 06 2f 0b 03 6f 4e 00 00 0a 04 fe 04 2b 01 16 0c 08 2d da } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}