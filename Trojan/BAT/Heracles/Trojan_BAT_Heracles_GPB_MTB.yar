
rule Trojan_BAT_Heracles_GPB_MTB{
	meta:
		description = "Trojan:BAT/Heracles.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 6f 06 00 00 0a 61 d2 52 11 06 17 58 13 06 11 06 07 8e 69 fe 04 13 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}