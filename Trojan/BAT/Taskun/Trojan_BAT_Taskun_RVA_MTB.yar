
rule Trojan_BAT_Taskun_RVA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.RVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 08 09 6f ?? 00 00 0a 13 04 07 12 04 28 ?? 00 00 0a 6f ?? 00 00 0a 00 0e 04 2d 02 2b 0e 0e 04 07 6f ?? 00 00 0a 6f ?? 00 00 0a 00 17 13 05 38 85 00 00 00 11 05 17 fe 01 13 0c 11 0c 2c 3c 00 07 6f ?? 00 00 0a 03 fe 04 16 fe 01 13 0d 11 0d 2c 02 2b 6d 07 12 04 28 ?? 00 00 0a 6f ?? 00 00 0a 00 0e 04 2d 02 2b 0e 0e 04 07 6f ?? 00 00 0a 6f ?? 00 00 0a 00 18 13 05 2b 3e 07 6f ?? 00 00 0a 03 fe 04 16 fe 01 13 0e 11 0e 2c 02 2b 32 07 12 04 28 ?? 00 00 0a 6f ?? 00 00 0a 00 0e 04 2d 02 2b 0e 0e 04 07 6f ?? 00 00 0a 6f ?? 00 00 0a 00 09 17 58 0d } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}