
rule Trojan_BAT_Amadey_RDY_MTB{
	meta:
		description = "Trojan:BAT/Amadey.RDY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 04 66 5f 03 66 04 5f 60 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}