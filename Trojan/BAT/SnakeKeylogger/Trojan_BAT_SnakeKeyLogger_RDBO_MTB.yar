
rule Trojan_BAT_SnakeKeyLogger_RDBO_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 08 18 6f 15 00 00 0a 1f 10 28 16 00 00 0a 6f 17 00 00 0a 08 18 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}