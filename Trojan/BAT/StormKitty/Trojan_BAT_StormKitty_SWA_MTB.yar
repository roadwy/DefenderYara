
rule Trojan_BAT_StormKitty_SWA_MTB{
	meta:
		description = "Trojan:BAT/StormKitty.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 20 00 01 00 00 6f ?? 00 00 0a 09 20 80 00 00 00 6f ?? 00 00 0a 7e 04 00 00 04 7e 03 00 00 04 20 e8 03 00 00 73 47 00 00 0a 13 04 09 11 04 09 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 09 11 04 09 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 09 17 6f ?? 00 00 0a 08 09 6f ?? 00 00 0a 17 73 4f 00 00 0a 13 05 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}