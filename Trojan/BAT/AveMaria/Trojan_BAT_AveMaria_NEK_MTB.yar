
rule Trojan_BAT_AveMaria_NEK_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 73 10 00 00 0a 28 11 00 00 0a 74 ?? 00 00 01 6f ?? 00 00 0a 74 ?? 00 00 01 73 13 00 00 0a 0a 25 6f 14 00 00 0a 06 6f 15 00 00 0a 6f 16 00 00 0a 06 6f 17 00 00 0a 06 6f 18 00 00 0a 0b dd } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}