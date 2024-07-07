
rule Trojan_BAT_Remcos_RDN_MTB{
	meta:
		description = "Trojan:BAT/Remcos.RDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {91 11 06 11 06 09 95 11 06 11 04 95 58 20 ff 00 00 00 5f 95 61 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}