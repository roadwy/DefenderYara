
rule Trojan_BAT_KeyLogger_SEDA_MTB{
	meta:
		description = "Trojan:BAT/KeyLogger.SEDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 11 05 28 ?? 00 00 0a 72 2a 04 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 11 05 28 ?? 00 00 0a 72 3c 04 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 7e 16 00 00 04 19 73 10 00 00 0a 0d 09 6f ?? 00 00 0a 69 13 07 09 11 05 6f ?? 00 00 0a 16 73 13 00 00 0a 0b 07 11 04 7e 15 00 00 04 16 94 11 07 6f ?? 00 00 0a 26 72 ?? ?? ?? 70 13 06 72 ?? ?? ?? 70 0a 11 04 28 ?? 00 00 06 26 08 2a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}