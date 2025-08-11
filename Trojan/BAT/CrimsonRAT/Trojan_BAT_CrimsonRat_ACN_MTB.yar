
rule Trojan_BAT_CrimsonRat_ACN_MTB{
	meta:
		description = "Trojan:BAT/CrimsonRat.ACN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 2b 06 02 7b ?? 00 00 04 13 09 02 7b ?? 00 00 04 11 06 08 11 09 6f ?? 00 00 0a 00 08 11 09 d6 0c 07 11 09 da 0b 00 07 16 fe 02 13 0b 11 0b 2d c6 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}