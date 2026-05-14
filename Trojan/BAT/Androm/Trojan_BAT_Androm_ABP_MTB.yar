
rule Trojan_BAT_Androm_ABP_MTB{
	meta:
		description = "Trojan:BAT/Androm.ABP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 14 11 15 6f ?? 00 00 0a 13 16 19 8d ?? 00 00 01 25 16 12 16 28 ?? 00 00 0a 9c 25 17 12 16 28 ?? 00 00 0a 9c 25 18 12 16 28 ?? 00 00 0a 9c 13 17 16 13 19 2b 7b } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}