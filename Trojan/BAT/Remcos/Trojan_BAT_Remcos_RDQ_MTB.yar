
rule Trojan_BAT_Remcos_RDQ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.RDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 27 00 00 0a 6f 28 00 00 0a 0b 73 29 00 00 0a 0c 08 07 17 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}