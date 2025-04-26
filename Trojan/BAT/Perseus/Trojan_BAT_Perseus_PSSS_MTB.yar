
rule Trojan_BAT_Perseus_PSSS_MTB{
	meta:
		description = "Trojan:BAT/Perseus.PSSS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 28 2f 00 00 06 13 08 11 08 02 1a 02 8e 69 1a 59 6f 72 00 00 0a 28 41 00 00 06 0c de 2d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}