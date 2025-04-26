
rule Trojan_BAT_njRAT_RDV_MTB{
	meta:
		description = "Trojan:BAT/njRAT.RDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 02 28 46 00 00 0a 0d 09 8e 69 08 8e 69 59 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}