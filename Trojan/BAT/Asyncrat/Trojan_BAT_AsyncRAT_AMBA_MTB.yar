
rule Trojan_BAT_AsyncRAT_AMBA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 07 08 16 73 ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 09 11 04 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 05 de 34 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}