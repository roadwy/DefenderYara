
rule Trojan_BAT_Heracles_PSUD_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PSUD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 02 7b 06 00 00 04 04 6f ?? 00 00 0a 16 05 6f ?? 00 00 0a 00 02 7b 09 00 00 04 04 05 02 7b 06 00 00 04 05 28 ?? 00 00 06 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}