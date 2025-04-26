
rule Trojan_BAT_Seraph_AAUV_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAUV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 07 11 01 03 11 01 91 11 03 61 d2 9c 38 ?? 00 00 00 11 02 11 09 11 01 94 58 11 05 11 01 94 58 20 00 01 00 00 5d 13 02 38 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}