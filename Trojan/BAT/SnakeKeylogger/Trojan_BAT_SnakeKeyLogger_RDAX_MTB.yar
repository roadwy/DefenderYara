
rule Trojan_BAT_SnakeKeyLogger_RDAX_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 06 6f 63 00 00 0a 06 6f 64 00 00 0a 6f 65 00 00 0a 0b 02 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}