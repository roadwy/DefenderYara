
rule Trojan_BAT_Seraph_FTAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.FTAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 00 16 11 00 8e 69 28 90 01 01 00 00 0a 20 00 00 00 00 7e 90 01 01 00 00 04 7b 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}