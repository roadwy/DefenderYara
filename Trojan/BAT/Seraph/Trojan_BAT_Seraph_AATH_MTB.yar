
rule Trojan_BAT_Seraph_AATH_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AATH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 02 07 91 20 aa fb 13 b6 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 59 d2 9c 07 17 58 0b 07 02 8e 69 32 df 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}