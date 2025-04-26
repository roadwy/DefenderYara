
rule Trojan_BAT_Amadey_RDFN_MTB{
	meta:
		description = "Trojan:BAT/Amadey.RDFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 02 00 00 2b 14 16 8d 13 00 00 01 6f 2b 00 00 0a 26 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}