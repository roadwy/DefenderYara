
rule Trojan_BAT_CrimsonRat_ACO_MTB{
	meta:
		description = "Trojan:BAT/CrimsonRat.ACO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 fe 01 13 07 11 07 2d 0b 02 72 ?? 00 00 70 7d ?? 00 00 04 72 ?? 05 00 70 28 ?? 00 00 0a 13 04 02 7b ?? 00 00 04 72 ?? 00 00 70 28 ?? 00 00 0a 16 fe 01 13 07 11 07 2d 0b 02 72 ?? 00 00 70 7d ?? 00 00 04 11 04 8e 69 17 fe 01 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}