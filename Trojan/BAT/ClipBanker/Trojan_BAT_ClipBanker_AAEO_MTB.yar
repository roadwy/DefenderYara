
rule Trojan_BAT_ClipBanker_AAEO_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.AAEO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {1e 2c 27 38 a5 00 00 00 38 a6 00 00 00 38 a7 00 00 00 00 38 ab 00 00 00 07 6f ?? 00 00 0a 07 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 02 73 ?? 00 00 0a 0d 00 09 08 16 73 ?? 00 00 0a 13 04 16 2d 01 00 73 ?? 00 00 0a 13 05 00 1d 2c fc 11 04 11 05 6f ?? 00 00 0a 00 11 05 6f ?? 00 00 0a 0a 1b 2c 01 00 de 0d 11 05 2c 08 11 05 6f ?? 00 00 0a 00 dc } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}