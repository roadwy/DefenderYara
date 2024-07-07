
rule Trojan_BAT_Heracles_AAXR_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AAXR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 8e 69 8d 90 01 01 00 00 01 0d 16 13 04 2b 18 09 11 04 08 11 04 91 06 11 04 06 8e 69 5d 91 61 d2 9c 11 04 17 58 13 04 11 04 08 8e 69 32 e1 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}