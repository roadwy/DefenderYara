
rule Trojan_BAT_Injuke_KAH_MTB{
	meta:
		description = "Trojan:BAT/Injuke.KAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 04 09 6f ?? 00 00 0a 13 05 12 05 28 ?? 00 00 0a 16 fe 01 13 06 11 06 2c 0b 00 08 6f ?? 00 00 0a 13 07 2b 39 08 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 11 04 17 58 13 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}