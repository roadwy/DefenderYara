
rule Trojan_BAT_Seraph_SPBN_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SPBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 05 16 73 90 01 03 0a 13 04 11 04 08 6f 90 01 03 0a 08 6f 90 01 03 0a 0b de 20 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}