
rule Trojan_BAT_Seraph_UZAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.UZAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {91 61 04 08 20 0f 02 00 00 58 20 0e 02 00 00 59 18 59 18 58 04 8e 69 5d 1f 09 58 1f 0b 58 1f 14 59 91 59 20 fb 00 00 00 58 1b 58 20 00 01 00 00 5d d2 9c 08 17 58 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}