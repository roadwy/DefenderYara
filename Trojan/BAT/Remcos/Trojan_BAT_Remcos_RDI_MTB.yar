
rule Trojan_BAT_Remcos_RDI_MTB{
	meta:
		description = "Trojan:BAT/Remcos.RDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 02 6f 1f 00 00 0a 25 26 0b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}