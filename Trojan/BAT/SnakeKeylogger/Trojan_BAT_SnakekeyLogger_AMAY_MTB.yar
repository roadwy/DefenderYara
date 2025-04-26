
rule Trojan_BAT_SnakekeyLogger_AMAY_MTB{
	meta:
		description = "Trojan:BAT/SnakekeyLogger.AMAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 58 08 5d 08 58 08 5d [0-28] 08 5d 08 58 [0-1e] 61 [0-0f] 58 20 00 01 00 00 5d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}