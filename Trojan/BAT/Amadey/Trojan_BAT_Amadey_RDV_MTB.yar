
rule Trojan_BAT_Amadey_RDV_MTB{
	meta:
		description = "Trojan:BAT/Amadey.RDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 02 11 06 28 01 00 00 2b 28 02 00 00 2b 16 11 06 8e 69 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}