
rule Trojan_BAT_AveMaria_PSSR_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.PSSR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 70 a2 25 19 28 ?? 00 00 06 a2 25 1a 72 7b 00 00 70 a2 25 1b 28 ?? 00 00 06 a2 25 1c 72 95 00 00 70 a2 25 1d 28 ?? 00 00 06 a2 28 ?? 00 00 0a 6f ?? 00 00 0a 80 03 00 00 04 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}