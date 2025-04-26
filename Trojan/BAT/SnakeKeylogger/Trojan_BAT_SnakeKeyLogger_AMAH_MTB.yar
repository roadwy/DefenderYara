
rule Trojan_BAT_SnakeKeyLogger_AMAH_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.AMAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {95 58 d2 13 [0-0f] 20 ff 00 00 00 5f 95 d2 [0-0f] 61 [0-0f] 20 ff 00 00 00 5f [0-14] 17 6a 58 13 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}