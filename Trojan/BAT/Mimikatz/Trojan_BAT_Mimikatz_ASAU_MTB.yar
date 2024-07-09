
rule Trojan_BAT_Mimikatz_ASAU_MTB{
	meta:
		description = "Trojan:BAT/Mimikatz.ASAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 04 11 05 6f ?? 00 00 0a 13 08 12 08 28 ?? 00 00 0a 28 ?? 00 00 0a 13 06 16 13 07 2b 1f 11 06 11 07 91 13 09 07 08 11 09 06 08 06 8e 69 5d 91 61 d2 9c 08 17 58 0c 11 07 17 58 13 07 11 07 11 06 8e 69 32 d9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}