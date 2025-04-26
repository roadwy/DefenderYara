
rule Trojan_BAT_AsyncRAT_KAD_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 06 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 07 11 07 11 05 16 11 05 8e 69 6f ?? 00 00 0a 11 07 6f ?? 00 00 0a dd ?? 00 00 00 11 07 39 ?? 00 00 00 11 07 6f ?? 00 00 0a dc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}