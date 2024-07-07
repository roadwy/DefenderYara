
rule Trojan_BAT_Remcos_RDM_MTB{
	meta:
		description = "Trojan:BAT/Remcos.RDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {59 20 00 00 01 00 58 20 00 00 01 00 5d 13 04 06 11 04 d1 13 05 12 05 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}