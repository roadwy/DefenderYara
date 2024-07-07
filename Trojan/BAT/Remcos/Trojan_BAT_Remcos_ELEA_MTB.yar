
rule Trojan_BAT_Remcos_ELEA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ELEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b f6 02 72 33 06 00 70 6f 90 01 03 0a 02 72 3f 06 00 70 6f 90 01 03 0a 02 72 75 06 00 70 6f 90 01 03 0a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}