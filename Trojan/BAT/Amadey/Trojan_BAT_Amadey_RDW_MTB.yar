
rule Trojan_BAT_Amadey_RDW_MTB{
	meta:
		description = "Trojan:BAT/Amadey.RDW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 0c 07 11 0c 91 06 11 0c 06 8e 69 5d 91 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}