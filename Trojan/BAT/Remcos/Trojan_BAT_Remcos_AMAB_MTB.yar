
rule Trojan_BAT_Remcos_AMAB_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 07 16 73 90 01 01 00 00 0a 13 04 11 04 08 6f 90 01 01 00 00 0a 08 6f 90 01 01 00 00 0a 13 05 de 20 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}