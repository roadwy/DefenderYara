
rule Trojan_BAT_njRAT_MBAB_MTB{
	meta:
		description = "Trojan:BAT/njRAT.MBAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 00 06 7e 90 01 01 00 00 04 6f 90 01 01 00 00 0a 00 06 18 6f 90 01 01 00 00 0a 00 06 18 6f 90 01 01 00 00 0a 00 06 6f 90 01 01 00 00 0a 0b 07 02 28 90 01 01 00 00 0a 16 02 28 90 01 01 00 00 0a 8e 69 6f 90 01 01 00 00 0a 0c 08 0d de 0b 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}