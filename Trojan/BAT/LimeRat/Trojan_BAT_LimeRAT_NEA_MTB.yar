
rule Trojan_BAT_LimeRAT_NEA_MTB{
	meta:
		description = "Trojan:BAT/LimeRAT.NEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {70 18 18 28 90 01 01 00 00 06 0b 28 90 01 01 00 00 0a 07 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 14 14 6f 90 01 01 00 00 0a 74 90 01 01 00 00 01 0c 2a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}