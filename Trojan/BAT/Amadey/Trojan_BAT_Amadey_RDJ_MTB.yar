
rule Trojan_BAT_Amadey_RDJ_MTB{
	meta:
		description = "Trojan:BAT/Amadey.RDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 11 09 16 11 09 8e 69 6f b4 00 00 0a 13 07 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}