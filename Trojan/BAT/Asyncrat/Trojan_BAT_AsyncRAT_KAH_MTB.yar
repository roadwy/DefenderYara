
rule Trojan_BAT_AsyncRAT_KAH_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.KAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 11 05 14 72 ?? 00 00 70 17 8d ?? 00 00 01 13 06 11 06 16 28 ?? 00 00 0a 03 6f ?? 00 00 0a a2 11 06 14 14 14 28 ?? 00 00 0a 74 ?? 00 00 1b 0c 2b 0c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}