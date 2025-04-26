
rule Trojan_BAT_AsyncRAT_SVCI_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.SVCI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 16 06 8e 69 6f ?? 04 00 0a 13 04 1c 2c ed de 37 09 2b de 07 2b dd 6f ?? 04 00 0a 2b d8 09 2b d7 08 2b d6 6f ?? 04 00 0a 2b d1 09 2b d0 6f ?? 04 00 0a 2b cb 1c 2c 09 09 2c 06 09 6f ?? 00 00 0a dc } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}