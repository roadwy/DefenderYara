
rule Trojan_BAT_Amadey_RDR_MTB{
	meta:
		description = "Trojan:BAT/Amadey.RDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 1f 30 28 05 00 00 2b 28 06 00 00 2b 0d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}