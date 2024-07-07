
rule Trojan_BAT_Remcos_AAMU_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AAMU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 07 75 90 01 01 00 00 1b 11 04 1e 8c 90 01 01 00 00 01 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 19 13 09 2b 90 01 01 08 17 d6 0c 1e 13 09 2b 87 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}