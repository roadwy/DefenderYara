
rule Trojan_BAT_SnakeLogger_FAR_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.FAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 01 2a 00 72 ?? 00 00 70 28 ?? 00 00 06 13 00 38 00 00 00 00 28 ?? 00 00 0a 11 00 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 06 13 01 38 00 00 00 00 dd } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}