
rule Trojan_BAT_CrimsonRat_ACR_MTB{
	meta:
		description = "Trojan:BAT/CrimsonRat.ACR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 41 00 11 04 02 7b ?? 00 00 04 30 04 11 04 2b 06 02 7b ?? 00 00 04 13 05 02 02 7b ?? 00 00 04 09 06 11 05 6f ?? 00 00 0a 7d ?? 00 00 04 06 02 7b } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}