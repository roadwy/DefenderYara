
rule Trojan_BAT_SnakeKeyLogger_RDBH_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 02 00 00 0a 72 01 00 00 70 28 03 00 00 0a 6f 04 00 00 0a 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}