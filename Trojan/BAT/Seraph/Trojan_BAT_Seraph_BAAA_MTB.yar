
rule Trojan_BAT_Seraph_BAAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.BAAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 06 08 91 7e 90 01 01 00 00 04 59 d2 9c 08 17 58 0c 08 06 8e 69 32 e9 07 2a 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}