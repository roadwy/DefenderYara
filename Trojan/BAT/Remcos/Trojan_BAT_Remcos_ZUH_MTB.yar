
rule Trojan_BAT_Remcos_ZUH_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ZUH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 05 11 06 6f ?? 00 00 0a 13 08 12 08 28 ?? 00 00 0a 13 09 12 08 28 ?? 00 00 0a 13 0a 12 08 28 ?? 00 00 0a 13 0b 11 09 28 ?? 00 00 06 13 09 11 0a 28 ?? 00 00 06 13 0a 11 0b } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}