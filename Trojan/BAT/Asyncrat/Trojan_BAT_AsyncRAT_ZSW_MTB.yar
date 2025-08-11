
rule Trojan_BAT_AsyncRAT_ZSW_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ZSW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 11 06 11 08 6f ?? 00 00 0a 13 09 11 04 11 05 8e 69 6f ?? 00 00 0a 13 0b 11 0b 2c 39 00 00 11 05 13 0c 16 13 0d } //6
		$a_03_1 = {01 25 16 12 09 28 ?? 00 00 0a 9c 25 17 12 09 28 ?? 00 00 0a 9c 25 18 12 09 28 ?? 00 00 0a 9c 13 13 16 13 14 2b 14 } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}