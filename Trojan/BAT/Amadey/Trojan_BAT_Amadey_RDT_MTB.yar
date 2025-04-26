
rule Trojan_BAT_Amadey_RDT_MTB{
	meta:
		description = "Trojan:BAT/Amadey.RDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 00 16 11 00 8e 69 28 02 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}