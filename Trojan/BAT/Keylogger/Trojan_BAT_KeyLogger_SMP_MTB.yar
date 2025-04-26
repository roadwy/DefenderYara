
rule Trojan_BAT_KeyLogger_SMP_MTB{
	meta:
		description = "Trojan:BAT/KeyLogger.SMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 06 00 00 04 18 6f ?? ?? ?? 0a 00 7e 06 00 00 04 6f ?? ?? ?? 0a 0a 2b 00 06 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}