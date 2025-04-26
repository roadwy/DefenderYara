
rule Trojan_BAT_AveMaria_AAVM_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.AAVM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 06 17 9a 74 ?? 00 00 01 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 16 0d 2b 16 00 08 09 08 09 91 06 18 9a a5 ?? 00 00 01 59 d2 9c 00 09 17 58 0d 09 08 8e 69 fe 04 13 04 11 04 2d de } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}