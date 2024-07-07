
rule Trojan_BAT_Heracles_NG_MTB{
	meta:
		description = "Trojan:BAT/Heracles.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 91 08 11 05 08 8e 69 5d 91 61 d2 90 01 02 00 00 0a 00 00 11 05 17 58 13 05 11 05 6a 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}