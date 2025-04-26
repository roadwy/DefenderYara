
rule Trojan_BAT_Remcos_RDK_MTB{
	meta:
		description = "Trojan:BAT/Remcos.RDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 26 0a 06 28 10 00 00 0a 25 26 0b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}