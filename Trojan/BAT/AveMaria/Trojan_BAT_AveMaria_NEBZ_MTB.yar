
rule Trojan_BAT_AveMaria_NEBZ_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 2b 16 06 09 28 ?? 00 00 06 13 04 07 09 11 04 6f ?? 00 00 0a 09 18 58 0d 09 06 6f ?? 00 00 0a 32 e1 } //5
		$a_03_1 = {02 03 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 2a } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}