
rule Trojan_BAT_SnakeKeyLogger_RDCH_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDCH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 07 1e 63 20 ff 00 00 00 5f d2 6f ab 00 00 0a 00 02 07 20 ff 00 00 00 5f d2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}