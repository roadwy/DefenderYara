
rule Trojan_BAT_DarkCloud_AEBB_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.AEBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 08 11 06 6f ?? 00 00 0a 13 07 08 02 6f ?? 00 00 0a 5a 11 06 58 13 08 19 8d ?? 00 00 01 25 16 12 07 28 ?? 00 00 0a 9c 25 17 12 07 28 ?? 00 00 0a 9c 25 18 12 07 28 ?? 00 00 0a 9c 13 09 12 07 28 ?? 00 00 0a 12 07 28 ?? 00 00 0a 58 12 07 28 ?? 00 00 0a 58 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}