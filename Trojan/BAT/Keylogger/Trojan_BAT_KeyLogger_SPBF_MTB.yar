
rule Trojan_BAT_KeyLogger_SPBF_MTB{
	meta:
		description = "Trojan:BAT/KeyLogger.SPBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 39 ea 06 00 00 09 1f 20 33 11 06 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 0a 38 d4 06 00 00 09 1f 0d 33 16 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}