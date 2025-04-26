
rule Trojan_BAT_AsyncRAT_KAT_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.KAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 06 8f ?? 00 00 01 25 71 ?? 00 00 01 11 06 0e 04 58 20 ff 00 00 00 5f d2 61 d2 81 ?? 00 00 01 1f 0e 13 12 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}