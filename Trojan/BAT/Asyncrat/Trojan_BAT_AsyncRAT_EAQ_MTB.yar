
rule Trojan_BAT_AsyncRAT_EAQ_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.EAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 06 0b 1f 20 8d ?? 00 00 01 25 d0 ?? 01 00 04 28 ?? 00 00 0a 0c 28 ?? 01 00 0a 03 6f ?? 00 00 0a 28 ?? 04 00 06 0d 73 ?? 01 00 0a 13 04 28 ?? 04 00 06 13 05 11 05 08 6f ?? 00 00 0a 11 05 09 6f ?? 01 00 0a 11 04 11 05 6f ?? 02 00 0a 17 73 ?? 01 00 0a 13 06 11 06 07 16 07 8e 69 6f ?? 01 00 0a 11 06 6f ?? 01 00 0a 11 04 6f ?? 01 00 0a 28 } //3
		$a_01_1 = {64 62 78 71 6c 63 75 79 2e 52 65 73 6f 75 72 63 65 73 } //2 dbxqlcuy.Resources
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}