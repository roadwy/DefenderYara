
rule Trojan_BAT_Seraph_EQAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.EQAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {59 91 61 03 08 20 8a 10 00 00 58 20 89 10 00 00 59 03 8e 69 5d 1f 09 58 1f 0e 58 1f 17 59 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 08 17 58 0c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}