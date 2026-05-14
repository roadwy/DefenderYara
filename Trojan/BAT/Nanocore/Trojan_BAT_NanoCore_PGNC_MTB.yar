
rule Trojan_BAT_NanoCore_PGNC_MTB{
	meta:
		description = "Trojan:BAT/NanoCore.PGNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 0a 11 0b 6f ?? 00 00 0a 13 0d 12 0d 28 ?? 00 00 0a 06 07 6f ?? 00 00 0a 59 13 0f 25 1f 10 63 20 ff 00 00 00 5f d2 13 13 25 1e 63 20 ff 00 00 00 5f d2 13 14 16 63 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}