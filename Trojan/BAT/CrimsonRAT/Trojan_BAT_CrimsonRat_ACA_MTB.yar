
rule Trojan_BAT_CrimsonRat_ACA_MTB{
	meta:
		description = "Trojan:BAT/CrimsonRat.ACA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 06 2b 40 11 06 02 7b ?? 00 00 04 30 04 11 06 2b 06 02 7b ?? 00 00 04 13 08 02 7b ?? 00 00 04 11 04 11 05 11 08 6f ?? 00 00 0a 11 05 11 08 58 13 05 11 06 11 08 59 13 06 02 28 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}