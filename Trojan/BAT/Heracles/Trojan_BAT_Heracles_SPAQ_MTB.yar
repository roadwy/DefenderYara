
rule Trojan_BAT_Heracles_SPAQ_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SPAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 72 01 00 00 70 28 90 01 03 0a 6f 90 01 03 0a 06 72 5b 00 00 70 28 90 01 03 0a 6f 90 01 03 0a 06 06 6f 90 01 03 0a 06 6f 90 01 03 0a 6f 90 01 03 0a 0b 73 08 00 00 0a 0c 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}