
rule Trojan_BAT_KeyLogger_SO_MTB{
	meta:
		description = "Trojan:BAT/KeyLogger.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 06 08 91 1f 1a 59 1f 1f 58 1f 15 59 1e 59 1f 21 59 d2 6f 0a 00 00 0a 08 17 58 0c 08 06 8e 69 32 de } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}