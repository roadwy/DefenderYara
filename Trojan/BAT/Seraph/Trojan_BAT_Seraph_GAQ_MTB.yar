
rule Trojan_BAT_Seraph_GAQ_MTB{
	meta:
		description = "Trojan:BAT/Seraph.GAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 13 04 16 13 05 11 04 12 05 28 90 01 01 00 00 0a 08 07 09 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a dd 90 01 01 00 00 00 11 05 39 90 01 01 00 00 00 11 04 28 90 01 01 00 00 0a dc 09 18 58 0d 09 07 6f 90 01 01 00 00 0a 32 bb 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}