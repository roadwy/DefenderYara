
rule Trojan_BAT_AsyncRAT_WRT_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.WRT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {1a 8d 0b 00 00 01 0b 06 07 16 07 8e 69 6f ?? 00 00 0a 26 07 16 28 ?? 00 00 0a 0c 06 16 73 14 00 00 0a 0d 08 8d 0b 00 00 01 13 04 16 13 05 38 13 00 00 00 11 05 09 11 04 11 05 08 11 05 59 6f ?? 00 00 0a 58 13 05 11 05 08 32 e8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}