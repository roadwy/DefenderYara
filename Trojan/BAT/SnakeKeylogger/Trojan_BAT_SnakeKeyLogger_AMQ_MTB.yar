
rule Trojan_BAT_SnakeKeyLogger_AMQ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.AMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {95 58 20 ff 00 00 00 5f 13 [0-32] 95 58 20 ff 00 00 00 5f 13 [0-1e] 61 13 [0-0f] d2 9c [0-0a] 17 58 13 [0-12] 8e 69 6a 32 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}