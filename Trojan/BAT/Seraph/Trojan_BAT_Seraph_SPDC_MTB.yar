
rule Trojan_BAT_Seraph_SPDC_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SPDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 01 00 00 0a 72 01 00 00 70 28 90 01 03 0a 0a 06 16 06 8e 69 28 90 01 03 0a dd 09 00 00 00 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}