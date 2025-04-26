
rule Trojan_BAT_SnakeKeyLogger_AMDA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.AMDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 11 ?? 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 ?? 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 ?? 20 ff 00 00 00 5f d2 9c 6f ?? 00 00 0a 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}