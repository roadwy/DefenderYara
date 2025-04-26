
rule Trojan_BAT_Cassiopeia_ACA_MTB{
	meta:
		description = "Trojan:BAT/Cassiopeia.ACA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 06 18 6f 37 00 00 0a 06 6f 38 00 00 0a 13 04 02 0d 11 04 09 16 09 8e b7 6f 39 00 00 0a 0b de 11 de 0f 25 28 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}