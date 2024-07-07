
rule Trojan_BAT_KeyLogger_SPQP_MTB{
	meta:
		description = "Trojan:BAT/KeyLogger.SPQP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 94 13 07 09 11 05 08 11 05 91 11 07 61 d2 9c 11 05 17 58 13 05 11 05 08 8e 69 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}