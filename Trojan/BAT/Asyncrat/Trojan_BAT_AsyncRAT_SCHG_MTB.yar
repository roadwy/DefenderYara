
rule Trojan_BAT_AsyncRAT_SCHG_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.SCHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 02 16 09 16 09 8e 69 28 ?? 00 00 0a 06 09 6f ?? 00 00 0a 02 8e 69 09 8e 69 59 8d 1c 00 00 01 13 04 02 09 8e 69 11 04 16 11 04 8e 69 28 ?? 00 00 0a 06 6f ?? 00 00 0a 13 05 11 05 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 06 de 20 11 05 2c 07 11 05 6f ?? 00 00 0a dc } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}