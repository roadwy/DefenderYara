
rule Trojan_BAT_AveMaria_RDG_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.RDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 10 00 00 0a 13 04 11 04 06 07 6f 11 00 00 0a 13 05 73 01 00 00 0a 13 06 11 06 11 05 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}