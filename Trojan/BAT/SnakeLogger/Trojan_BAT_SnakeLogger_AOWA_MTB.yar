
rule Trojan_BAT_SnakeLogger_AOWA_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.AOWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {70 0b 06 8e 69 8d ?? 00 00 01 0c 16 0d 38 ?? 00 00 00 08 09 06 09 91 07 09 07 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 09 17 58 0d 09 06 8e 69 32 e0 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}