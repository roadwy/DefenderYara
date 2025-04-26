
rule Trojan_BAT_Remcos_RDR_MTB{
	meta:
		description = "Trojan:BAT/Remcos.RDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 08 5d 08 58 08 5d 91 11 07 61 11 09 59 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}