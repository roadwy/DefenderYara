
rule Trojan_BAT_Coins_AAFQ_MTB{
	meta:
		description = "Trojan:BAT/Coins.AAFQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 06 16 06 8e 69 6f ?? 01 00 0a 0b 07 16 fe 02 13 06 11 06 2c 0b 11 05 06 16 07 6f ?? 00 00 0a 00 16 13 07 2b 2e 00 03 7e ?? 00 00 04 03 7b ?? 00 00 04 06 11 07 91 61 20 ff 00 00 00 5f 95 03 7b ?? 00 00 04 1e 64 61 7d ?? 00 00 04 00 11 07 17 58 13 07 11 07 6e 07 6a fe 04 13 08 11 08 2d c5 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}