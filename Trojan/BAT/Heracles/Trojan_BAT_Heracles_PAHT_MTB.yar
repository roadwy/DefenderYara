
rule Trojan_BAT_Heracles_PAHT_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PAHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 08 69 02 08 69 91 06 08 03 6f ?? 00 00 0a 6a 5d 69 91 61 9c 08 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}