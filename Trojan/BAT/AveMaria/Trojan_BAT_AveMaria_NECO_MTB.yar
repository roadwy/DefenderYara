
rule Trojan_BAT_AveMaria_NECO_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NECO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 07 11 09 9a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 09 17 58 13 09 11 09 07 8e 69 fe 04 13 0a 11 0a 2d db 08 6f ?? 00 00 0a 0d 09 28 ?? 00 00 0a 13 04 11 04 6f ?? 00 00 0a 17 9a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}