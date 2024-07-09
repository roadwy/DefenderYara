
rule Trojan_BAT_Seraph_SPBP_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SPBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 06 07 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 16 07 8e 69 6f ?? ?? ?? 0a de 03 26 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}